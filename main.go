// © 2025 Graylog, Inc.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"time"

	"ebpf-logger/helpers"
	wl "ebpf-logger/helpers/wlog"

	"github.com/cilium/ebpf/ringbuf"
	logger "github.com/resurfaceio/logger-go/v3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sys/unix"
)

const POISON uint64 = 0x8D0003048D0304F0
const SEP string = "🗣️ 📢 🔥🔥🔥"

type parsedMessage struct {
	httpReq        http.Request
	httpResp       http.Response
	isHttp2        bool
	responseMillis int64
	interval       int64
}

type rawMessage struct {
	rawReq       []byte
	rawResp      []byte
	createdAt    time.Time
	reqTime      time.Time
	respTime     time.Time
	isHttp2      bool
	isReqClosed  bool
	isRespClosed bool
	isParsed     bool
	id           [20]byte
	sslp         uint64
}

type rawRecord struct {
	raw   *[]byte
	isReq bool
}

var crlf []byte = []byte("\r\n")
var httpbar []byte = []byte("HTTP/")

var wlog *wl.Wlogger
var messages map[[20]byte]*rawMessage
var toIngest chan *rawRecord
var toParse chan *rawMessage
var toProcess chan *parsedMessage
var l *logger.HttpLogger

func getNanoKtime() uint64 {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return 0
	}

	return uint64(unix.TimespecToNsec(ts))
}

func main() {
	defer wl.Println("Thanks for using Graylog! 👋")

	wlog = wl.NewWrappedLogger(os.Getenv("USAGE_LOGGERS_EBPF_LOG_LEVEL"), wl.ERROR)

	isClient := os.Getenv("USAGE_LOGGERS_EBPF_ROLE") == "client"

	exPath, exists := os.LookupEnv("USAGE_LOGGERS_EBPF_EXPATH")
	if !exists {
		wl.Fatalln("USAGE_LOGGERS_EBPF_EXPATH not set")
	}

	wlog.Println(wl.DEBUG, "Executable: ", exPath)

	// Load programs
	//---------------------------------------------------------
	closers := load(exPath, isClient)
	for _, c := range closers {
		defer c.Close()
	}

	// Retrieve maps
	//---------------------------------------------------------

	objs, ok := closers[0].(*loggerObjects)
	if !ok {
		wl.Panic("error trying to access maps: first item is not *loggerObjects")
	}

	// Define structures to receive data
	//---------------------------------------------------------

	readsReader, err := ringbuf.NewReader(objs.Reads)
	if err != nil {
		wl.Panicf("opening ringbuf reader: %s", err)
	}
	defer readsReader.Close()

	writesReader, err := ringbuf.NewReader(objs.Writes)
	if err != nil {
		wl.Panicf("opening ringbuf reader: %s", err)
	}
	defer writesReader.Close()

	messages = make(map[[20]byte]*rawMessage)
	toIngest = make(chan *rawRecord)
	toParse = make(chan *rawMessage)
	toProcess = make(chan *parsedMessage)

	go readRing(readsReader, true, isClient)
	go readRing(writesReader, false, isClient)

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	//---------------------------------------------------------

	opts := logger.Options{Rules: os.Getenv("USAGE_LOGGERS_RULES")}
	l, err = logger.NewHttpLogger(opts)
	if err != nil {
		wlog.Println(wl.ERROR, "initializing logger: ", err)
		return
	}
	if !l.Enabled() {
		wlog.Println(wl.ERROR, "logger is not enabled")
		return
	}

	if !l.IsFlukeReachable() {
		wlog.Println(wl.WARN, "warning: could not reach fluke during logger initialization")
	} else {
		wlog.Println(wl.INFO, "Graylog fluke server is reachable.")
	}

	wlog.Println(wl.INFO, "HTTPS logger is initialized.")
	wlog.Println(wl.DEBUG, "  url:   ", os.Getenv("USAGE_LOGGERS_URL"))
	wlog.Println(wl.DEBUG, "  rules: ", opts.Rules)
	wlog.Println(wl.INFO, "Waiting for any HTTPS payloads from OpenSSL calls...")

	go process()
	go parse()
	go ingest()

	var (
		key     uint64
		stash   loggerStashT
		counter loggerCounterT
	)

	for {
		select {
		case <-stop:
			wl.Println("Received signal, exiting...")

			if err := readsReader.Flush(); err != nil {
				wlog.Printf(wl.ERROR, "flushing ringbuf reads reader: %s", err)
				return
			}
			if err := readsReader.Close(); err != nil {
				wlog.Printf(wl.ERROR, "closing ringbuf reads reader: %s", err)
				return
			}

			if err := writesReader.Flush(); err != nil {
				wlog.Printf(wl.ERROR, "flushing ringbuf writes reader: %s", err)
				return
			}
			if err := writesReader.Close(); err != nil {
				wlog.Printf(wl.ERROR, "closing ringbuf writes reader: %s", err)
				return
			}
			return

		default:
			entries := objs.Stashes.Iterate()

			for entries.Next(&key, &stash) {
				now := getNanoKtime()
				delta := time.Duration(now - stash.CreatedAt)
				ssl := stash.Ssl
				err = objs.Counts.Lookup(&ssl, &counter)
				if err != nil {
					var id [20]byte
					binary.LittleEndian.PutUint64(id[:8], key)
					binary.LittleEndian.PutUint64(id[8:16], ssl)
					binary.LittleEndian.PutUint32(id[16:20], counter.Count)
					tgid := binary.LittleEndian.Uint32(id[:4])
					wlog.Printf(wl.TRACE, "[MAIN] Checking stash with ID=[%032x], PID_TGID=[%016x] (PID=%d), and *SSL=[%016x|%08x], and TS=%d (now=%d)\n",
						id,
						key,
						tgid,
						ssl,
						counter.Count,
						stash.CreatedAt,
						now,
					)

					if _, exists := messages[id]; !exists && delta > 5*time.Second {
						objs.Stashes.Delete(&key)
						wlog.Printf(wl.TRACE, "[MAIN] Stash [%016x] timed out! Stash was deleted from BPF map.", id)
					}
				}
			}

			if err := entries.Err(); err != nil {
				wlog.Println(wl.ERROR, "[MAIN] Stashes map iterator encountered an error:", err)
				return
			}

			entries = objs.Counts.Iterate()

			for entries.Next(&key, &counter) {
				delta := time.Duration(getNanoKtime() - counter.LastUpdated)
				if delta > 3*time.Hour && counter.Lock == ^uint32(0) {
					objs.Counts.Delete(&key)
					wlog.Printf(wl.TRACE, "[MAIN] Counter [%016x] timed out! Count was deleted from BPF map.", key)
				}

			}

			if err = entries.Err(); err != nil {
				wlog.Println(wl.ERROR, "[MAIN] Counts map iterator encountered an error:", err)
				return
			}

			time.Sleep(3 * time.Second)
		}
	}
}

func readRing(reader *ringbuf.Reader, fromReads bool, isClient bool) {
	name := "reads"
	if !fromReads {
		name = "writes"
	}
	for {
		if received, err := reader.Read(); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				wlog.Println(wl.INFO, "closing ingestion channel...")
				select {
				case _, ok := <-toIngest:
					if ok {
						close(toIngest)
					}
				default:
					close(toIngest)
				}
				return
			}
			wlog.Printf(wl.INFO, "reading from %s reader: %s", name, err)
			continue
		} else {
			toIngest <- &rawRecord{
				raw:   &received.RawSample,
				isReq: fromReads != isClient,
			}
		}
	}
}

func parse() {
	for message := range toParse {
		if !message.isParsed && len(message.rawReq) != 0 && len(message.rawResp) != 0 {
			var done bool
			var parsed *parsedMessage
			for !done {
				parsed, done = parseFirstFound(message)
				if parsed != nil {
					message.isParsed = true
					wlog.Printf(wl.DEBUG, "[PARSE] Message [%16x] successfully parsed.", message.id)
					wlog.Printf(wl.TRALL, "[PARSE] Raw %s: [% x]\n", "Request", message.rawReq)
					wlog.Printf(wl.TRALL, "[PARSE] Raw %s: [% x]\n", "Response", message.rawResp)
					toProcess <- parsed
				}
			}
		}
	}
}

func ingest() {
	for record := range toIngest {
		raw := *record.raw
		isReq := record.isReq
		data := helpers.ParseDataHeaders(raw)
		if data == nil {
			return
		}
		now := time.Now()
		payload := data.GetPayload(raw)
		id := data.GetId()

		message, isPresent := messages[id]

		if label := "RESP"; wlog.GetLevel() >= wl.DEBUG {
			if isReq {
				label = "REQ "
			}
			if !isPresent {
				wl.Println(SEP)
			}
			wl.Printf("[INGEST] %s - NEW RECORD (%-5d B) - SID: [%020x] (TGID: %d [%08x], SSL: [%016x|%d]) - TS: %d\n",
				label,
				data.PayloadLen,
				id,
				data.Tgid,
				data.Raw.Tgid,
				data.Raw.Sslp,
				data.Sslc,
				data.Ktime,
			)
			wlog.Printf(wl.TRALL, "[INGEST] %s - RAW RECORD: % x\n", label, payload)
		}

		if !isPresent {
			message = new(rawMessage)
			message.createdAt = now
			message.sslp = data.Sslp
			message.id = id

			if isReq {
				message.reqTime = now
				message.isHttp2 = len(payload) >= 24 && string(payload[:24]) == http2.ClientPreface
				if message.isHttp2 {
					payload = payload[24:]
				}
			} else {
				message.respTime = now
			}
			messages[id] = message
		} else {
			if len(message.rawReq) == 0 && isReq {
				message.reqTime = now
				message.isHttp2 = len(payload) >= 24 && string(payload[:24]) == http2.ClientPreface
				if message.isHttp2 {
					payload = payload[24:]
				}
			} else if len(message.rawResp) == 0 && !isReq {
				message.respTime = now
			}
		}

		if data.PayloadLen == 8 && binary.LittleEndian.Uint64(payload) == POISON {
			if isReq {
				message.isReqClosed = true
			} else {
				message.isRespClosed = true
			}
			if message.isReqClosed && message.isRespClosed {
				toParse <- message
				delete(messages, id)
				wlog.Printf(wl.TRACE, "[INGEST] Message [%016x] removed from messages map.", id)
			}
		} else if isReq {
			message.rawReq = append(message.rawReq, payload...)
		} else {
			message.rawResp = append(message.rawResp, payload...)
		}
	}

}

func parseHeaders(toParse []byte, existingHeaders http.Header) (headers http.Header) {
	if existingHeaders != nil {
		headers = http.Header.Clone(existingHeaders)
	} else {
		headers = http.Header{}
	}
	for _, line := range bytes.Split(toParse, crlf) {
		header := bytes.Split(line, []byte(": "))
		if len(header) < 2 {
			continue
		}
		headers.Add(string(header[0]), string(header[1]))
	}
	return
}

func parseFirstFound(message *rawMessage) (parsed *parsedMessage, consumed bool) {
	consumed = true
	parsed = new(parsedMessage)
	parsed.isHttp2 = message.isHttp2

	wlog.Printf(wl.TRACE, "[PARSE] Raw Message info <len(req), len(resp), isHttp2>: %d, %d, %v\n",
		len(message.rawReq),
		len(message.rawResp),
		message.isHttp2,
	)

	if !message.isHttp2 {
		// [first-line, headers, body+trailers]
		var req [3][]byte
		var resp [3][]byte

		// Slice first line, headers+body+trailers
		copy(req[:2], bytes.SplitN(message.rawReq, crlf, 2))
		copy(resp[:2], bytes.SplitN(message.rawResp, crlf, 2))

		// Slice headers, body+trailers
		copy(req[1:], bytes.SplitN(req[1], append(crlf, crlf...), 2))
		copy(resp[1:], bytes.SplitN(resp[1], append(crlf, crlf...), 2))

		// Request
		firstLine := bytes.Fields(req[0])

		if len(firstLine) <= 1 {
			wlog.Printf(wl.ERROR, "[PARSE] ERROR: couldn't parse message as HTTP1. Attempting again as HTTP2")
			message.isHttp2 = true
			return nil, false
		}

		// Method
		method := string(firstLine[0])

		// URL
		path := firstLine[1]
		if !bytes.Contains(path, []byte("://")) && !bytes.HasPrefix(path, []byte("/")) {
			path = append([]byte("/"), path...)
		}
		parsedUrl, err := url.Parse(string(path))
		if err != nil {
			wlog.Println(wl.ERROR, "parsing url: ", err)
			return nil, consumed
		}

		// Request headers
		reqHeaders := parseHeaders(req[1], nil)
		host := reqHeaders.Get("Host")

		// Response
		firstLine = bytes.Fields(resp[0])

		// Status code
		status, err := strconv.Atoi(string(firstLine[1]))
		if err != nil {
			wlog.Println(wl.ERROR, "parsing status code: ", err)
			return nil, consumed
		}

		// Response headers
		respHeaders := parseHeaders(resp[1], nil)

		// Split additional raw messages if present

		// Request
		if newReqIndex := bytes.Index(req[2], httpbar); newReqIndex != -1 {
			if newReqIndex = bytes.LastIndex(req[2][:newReqIndex], crlf); newReqIndex != -1 {
				message.rawReq = req[2][newReqIndex:]
				req[2] = req[2][:newReqIndex]
			} else {
				// empty body (all of req[2] is another request entirely)
				message.rawReq = req[2]
				req[2] = nil
			}
			consumed = false
		}

		// Response
		if newRespIndex := bytes.Index(resp[2], httpbar); newRespIndex != -1 {
			message.rawResp = resp[2][newRespIndex:]
			resp[2] = resp[2][:newRespIndex]
			consumed = false
		}

		// Trailers
		if len(req[2]) != 0 && reqHeaders.Get("Transfer-Encoding") == "chunked" && reqHeaders.Get("Trailer") != "" {
			lastChunkIndex := bytes.LastIndex(req[2], append([]byte("0"), crlf...)) + 3
			reqHeaders = parseHeaders(req[2][lastChunkIndex:], reqHeaders)
			req[2] = req[2][:lastChunkIndex]
		}

		if len(resp[2]) != 0 && respHeaders.Get("Transfer-Encoding") == "chunked" && respHeaders.Get("Trailer") != "" {
			lastChunkIndex := bytes.LastIndex(resp[2], append([]byte("0"), crlf...)) + 3
			respHeaders = parseHeaders(resp[2][lastChunkIndex:], respHeaders)
			resp[2] = resp[2][:lastChunkIndex]
		}

		// Bodies

		wlog.Printf(wl.TRACE, "[PARSE] Parsed body lengths <req, resp>: %d, %d\n", len(req[2]), len(resp[2]))
		wlog.Printf(wl.TRALL, "[PARSE] %s body: % x\n", "REQUEST", req[2])
		wlog.Printf(wl.TRALL, "[PARSE] %s body: % x\n", "RESPONSE", resp[2])

		// Wrap it up
		parsed.httpReq = http.Request{
			Method:        method,
			Host:          host,
			URL:           parsedUrl,
			Header:        reqHeaders,
			Body:          io.NopCloser(bytes.NewReader(req[2])),
			ContentLength: int64(len(req[2])),
			TLS:           &tls.ConnectionState{},
		}

		if parsedUrl.IsAbs() {
			parsed.httpReq.RequestURI = string(path)
		}

		parsed.httpResp = http.Response{
			StatusCode:    status,
			Header:        respHeaders,
			Body:          io.NopCloser(bytes.NewReader(resp[2])),
			ContentLength: int64(len(resp[2])),
		}

	} else {
		var method, host string
		var status int
		var reqBody, respBody []byte
		parsedUrl := &url.URL{}
		reqHeaders := http.Header{}
		respHeaders := http.Header{}

		for i, raw := range [][]byte{message.rawReq, message.rawResp} {
			label := "REQ "
			if i != 0 {
				label = "RESP"
			}
			for _, frame := range toFrames(raw) {
				wlog.Printf(wl.TRALL, "[PARSE] %s - RAW FRAME: % x", label, frame._raw)
				wlog.Printf(wl.TRALL, "[PARSE] %s - PARSED FRAME\n\tLength: %d [% x]\n\tType: % x\n\tFlag: % x\n\tStream ID: %d [% x]\n\tRaw Data: % x\n",
					label,
					frame._lend,
					frame._len,
					frame._type,
					frame._flag,
					frame._streamIDd,
					frame._streamID,
					frame._data,
				)

				if frame._type == HEADERS {
					decoder := hpack.NewDecoder(4096, nil)
					headers, err := decoder.DecodeFull(frame._data)
					if err != nil {
						wl.Println("decoding headers: ", err)
						continue
					}

					wlog.Printf(wl.DEBUG, "[PARSE] %s - HEADERS\n", label)

					for _, header := range headers {
						switch header.Name {
						case ":method":
							method = header.Value
						case ":scheme":
							parsedUrl.Scheme = header.Value
						case ":authority":
							host = header.Value
							parsedUrl.Host = header.Value
						case ":path":
							pathQuery, err := url.ParseRequestURI(header.Value)
							if err != nil {
								wlog.Println(wl.ERROR, "decoding path: ", err)
								return nil, false
							}
							parsedUrl.Path = pathQuery.Path
							parsedUrl.RawQuery = pathQuery.RawQuery
						case ":status":
							status, err = strconv.Atoi(header.Value)
							if err != nil {
								wlog.Println(wl.ERROR, "parsing url: ", err)
								return nil, false
							}
						default:
							if i == 0 {
								reqHeaders.Add(header.Name, header.Value)
							} else {
								respHeaders.Add(header.Name, header.Value)
							}
						}
						wlog.Println(wl.DEBUG, header.Name+":"+header.Value)
					}
				}

				if frame._type == DATA {
					if i == 0 {
						reqBody = append(reqBody, frame._data...)
					} else {
						respBody = append(respBody, frame._data...)
					}

					wlog.Printf(wl.DEBUG, "[PARSE] %s - DATA LENGTH: %d\n", label, len(frame._data))
					wlog.Printf(wl.TRALL, "[PARSE] %s - DATA: %s\n", label, frame._data)
				}

				wlog.Println(wl.TRALL, SEP)
			}

			// Wrap it up
			parsed.httpReq = http.Request{
				Method:        method,
				Host:          host,
				URL:           parsedUrl,
				Header:        reqHeaders,
				Body:          io.NopCloser(bytes.NewReader(reqBody)),
				ContentLength: int64(len(reqBody)),
				TLS:           &tls.ConnectionState{},
			}

			if parsedUrl.IsAbs() {
				parsed.httpReq.RequestURI = parsedUrl.String()
			}

			parsed.httpResp = http.Response{
				StatusCode:    status,
				Header:        respHeaders,
				Body:          io.NopCloser(bytes.NewReader(respBody)),
				ContentLength: int64(len(respBody)),
			}
		}

	}

	parsed.responseMillis = message.respTime.UnixMilli()
	parsed.interval = message.respTime.Sub(message.reqTime).Abs().Milliseconds()

	return parsed, consumed
}

func process() {
	for {
		message := <-toProcess
		if message != nil {
			if wlog.GetLevel() >= wl.DEBUG {
				wl.Println(SEP)
				wl.Println("[PROCESS] Request: ", message.httpReq)
				wl.Println("[PROCESS] Response: ", message.httpResp)
				wl.Println("[PROCESS] Response time: ", message.responseMillis)
				wl.Println("[PROCESS] Interval: ", message.interval)
				wl.Printf("[PROCESS] Message is HTTP2: %v\n", message.isHttp2)

				if wlog.GetLevel() >= wl.TRALL {
					body, err := io.ReadAll(message.httpReq.Body)
					if err == nil {
						wl.Printf("[PROCESS] Request body %v:\n%s\n", message.httpReq.Body, body)
						message.httpReq.Body.Close()
						message.httpReq.Body = io.NopCloser(bytes.NewReader(body))
					}

					body, err = io.ReadAll(message.httpResp.Body)
					if err == nil {
						wl.Printf("[PROCESS] Response body %v:\n%s\n", message.httpResp.Body, body)
						message.httpResp.Body.Close()
						message.httpResp.Body = io.NopCloser(bytes.NewReader(body))
					}
				}
			}
			if l.IsFlukeReachable() {
				logger.SendHttpMessage(l, &message.httpResp, &message.httpReq, message.responseMillis, message.interval, nil)
			} else {
				wlog.Println(wl.ERROR, "[PROCESS] Could not send message. Fluke server is not reachable at the moment")
				continue
			}
		}
	}
}
