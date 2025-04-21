// © 2025 Graylog, Inc.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	logger "github.com/resurfaceio/logger-go/v3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sys/unix"
)

const (
	NOLOG int = iota
	ERROR
	WARN
	INFO
	DEBUG
	TRACE
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
	id           uint64
	fd           uint32
}

type rawRecord struct {
	raw   *[]byte
	isReq bool
}

var LOG_LEVEL int = TRACE
var crlf []byte = []byte("\r\n")
var httpbar []byte = []byte("HTTP/")

var messages map[uint64]*rawMessage
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
	defer log.Println("All done. Bye!")

	if level, err := strconv.Atoi(os.Getenv("USAGE_LOGGERS_EBPF_LOG_LEVEL")); err == nil {
		if level < NOLOG {
			LOG_LEVEL = NOLOG
		} else {
			LOG_LEVEL = min(level, TRACE)
		}
	}

	isClient := os.Getenv("USAGE_LOGGERS_EBPF_ROLE") == "client"

	exPath, exists := os.LookupEnv("USAGE_LOGGERS_EBPF_EXPATH")
	if !exists {
		log.Fatalln("USAGE_LOGGERS_EBPF_EXPATH not set")
	}

	if LOG_LEVEL >= DEBUG {
		log.Println("executable: ", exPath)
	}

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
		log.Panic("error trying to access maps: first item is not *loggerObjects")
	}

	// Define structures to receive data
	//---------------------------------------------------------

	readsReader, err := ringbuf.NewReader(objs.Reads)
	if err != nil {
		log.Panicf("opening ringbuf reader: %s", err)
	}
	defer readsReader.Close()

	writesReader, err := ringbuf.NewReader(objs.Writes)
	if err != nil {
		log.Panicf("opening ringbuf reader: %s", err)
	}
	defer writesReader.Close()

	messages = make(map[uint64]*rawMessage)
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
		if LOG_LEVEL >= ERROR {
			log.Println("initializing logger: ", err)
		}
		return
	}
	if !l.Enabled() {
		if LOG_LEVEL >= ERROR {
			log.Println("logger is not enabled")
		}
		return
	}
	if LOG_LEVEL >= INFO {
		log.Println("logger is initialized")
		if LOG_LEVEL >= DEBUG {
			log.Println("  url:   ", os.Getenv("USAGE_LOGGERS_URL"))
			log.Println("  rules: ", opts.Rules)
		}
		log.Println("Waiting for any OpenSSL calls...")
	}

	go process()
	go parse()
	go ingest()

	var (
		key   uint64
		value loggerTraceT
	)

	for {
		select {
		case <-stop:
			log.Println("Received signal, exiting...")

			if err := readsReader.Flush(); err != nil {
				if LOG_LEVEL >= ERROR {
					log.Printf("flushing ringbuf reads reader: %s", err)
				}
				return
			}
			if err := readsReader.Close(); err != nil {
				if LOG_LEVEL >= ERROR {
					log.Printf("closing ringbuf reads reader: %s", err)
				}
				return
			}

			if err := writesReader.Flush(); err != nil {
				if LOG_LEVEL >= ERROR {
					log.Printf("flushing ringbuf writes reader: %s", err)
				}
				return
			}
			if err := writesReader.Close(); err != nil {
				if LOG_LEVEL >= ERROR {
					log.Printf("closing ringbuf writes reader: %s", err)
				}
				return
			}
			return

		default:
			entries := objs.Traces.Iterate()

			for entries.Next(&key, &value) {
				now := getNanoKtime()
				delta := time.Duration(now - value.Ts)
				pid := uint32(key)
				id := uint64(pid) | (uint64(value.Fd) << 32)
				if LOG_LEVEL >= TRACE {
					log.Printf("[MAIN] Checking trace with ID=[%016x], PID=[%08x] (%d) and FD=[%08x], and TS=%d (now=%d)\n", id, pid, pid, value.Fd, value.Ts, now)
					log.Printf("[MAIN] Trace flags: [%08x]", value.Flags)
				}
				if _, exists := messages[id]; !exists && delta > 5*time.Second {
					objs.Traces.Delete(&key)
					if LOG_LEVEL >= TRACE {
						log.Printf("[MAIN] Trace [%016x] timed out! Trace was deleted from BPF map.", id)
					}
				}
			}

			if err := entries.Err(); err != nil {
				if LOG_LEVEL >= ERROR {
					log.Println("[MAIN] Traces map iterator encountered an error:", err)
				}
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
				if LOG_LEVEL >= INFO {
					log.Println("closing ingestion channel...")
				}
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
			if LOG_LEVEL >= INFO {
				log.Printf("reading from %s reader: %s", name, err)
			}
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
			var isFinished bool
			var parsed *parsedMessage
			for !isFinished {
				parsed, isFinished = parseFirstFound(message)
				if parsed != nil {
					message.isParsed = true
					if LOG_LEVEL >= DEBUG {
						log.Printf("[MAIN] Message [%16x] successfully parsed.", message.id)
						if LOG_LEVEL >= TRACE {
							log.Printf("[MAIN] Raw Request: [% x]\n", message.rawReq)
							log.Printf("[MAIN] Raw Response: [% x]\n", message.rawResp)
						}
					}
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
		if len(raw) < 8 {
			return
		}
		now := time.Now()
		rawPid := raw[:4]
		rawFd := raw[4:8]
		pid := binary.LittleEndian.Uint32(rawPid)
		fd := binary.LittleEndian.Uint32(rawFd)
		payload := raw[8:]
		id := uint64(pid) | (uint64(fd) << 32)
		rawId := make([]byte, 8)
		binary.LittleEndian.PutUint64(rawId, id)

		message, isPresent := messages[id]

		if LOG_LEVEL >= DEBUG {
			t := "RESP"
			if isReq {
				t = "REQ"
			}
			if !isPresent {
				log.Println(SEP)
			}
			log.Printf("[INGEST] %s - NEW RECORD - TRACE ID: [%016x] (TGID: %d [%08x], FD: [%08x])\n", t, rawId, pid, rawPid, rawFd)
			if LOG_LEVEL >= TRACE {
				log.Printf("[INGEST] %s - RAW RECORD: % x\n", t, payload)
			}
		}

		if !isPresent {
			message = new(rawMessage)
			message.createdAt = now
			message.fd = fd
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

		if len(payload) == 8 && binary.LittleEndian.Uint64(payload) == POISON {
			if isReq {
				message.isReqClosed = true
			} else {
				message.isRespClosed = true
			}
			if message.isReqClosed && message.isRespClosed {
				toParse <- message
				delete(messages, id)
				if LOG_LEVEL >= TRACE {
					log.Printf("[MAIN] Message [%016x] removed from messages map.", id)
				}
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

	if LOG_LEVEL >= TRACE {
		log.Printf("[PARSE] Raw Message info <len(req), len(resp), isHttp2>: %d, %d, %v\n", len(message.rawReq), len(message.rawResp), message.isHttp2)
	}

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
			if LOG_LEVEL >= ERROR {
				log.Printf("[PARSE] ERROR: couldn't parse message as HTTP1. Attempting again as HTTP2")
			}
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
			if LOG_LEVEL >= ERROR {
				log.Println("parsing url: ", err)
			}
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
			if LOG_LEVEL >= ERROR {
				log.Println("parsing status code: ", err)
			}
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

		if LOG_LEVEL >= DEBUG {
			log.Printf("[PARSE] Request body: % x\n", req[2])
			log.Printf("[PARSE] Response body: % x\n", resp[2])
		}

		// Wrap it up
		parsed.httpReq = http.Request{
			Method:        method,
			Host:          host,
			URL:           parsedUrl,
			Header:        reqHeaders,
			Body:          io.NopCloser(bytes.NewReader(req[2])),
			ContentLength: int64(len(req[2])),
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
			label := "REQ"
			if i != 0 {
				label = "RESP"
			}
			for _, frame := range toFrames(raw) {
				if LOG_LEVEL >= TRACE {
					log.Printf("[PARSE] %s - RAW FRAME: % x", label, frame._raw)
					log.Printf("[PARSE] %s - PARSED FRAME\n\tLength: %d [% x]\n\tType: % x\n\tFlag: % x\n\tStream ID: %d [% x]\n\tRaw Data: % x\n",
						label,
						frame._lend,
						frame._len,
						frame._type,
						frame._flag,
						frame._streamIDd,
						frame._streamID,
						frame._data,
					)
				}

				if frame._type == HEADERS {
					decoder := hpack.NewDecoder(4096, nil)
					headers, err := decoder.DecodeFull(frame._data)
					if err != nil {
						log.Println("decoding headers: ", err)
						continue
					}

					if LOG_LEVEL >= DEBUG {
						log.Printf("[PARSE] %s - HEADERS\n", label)
					}

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
								if LOG_LEVEL >= ERROR {
									log.Println("decoding path: ", err)
								}
								return nil, false
							}
							parsedUrl.Path = pathQuery.Path
							parsedUrl.RawQuery = pathQuery.RawQuery
						case ":status":
							status, err = strconv.Atoi(header.Value)
							if err != nil {
								if LOG_LEVEL >= ERROR {
									log.Println("parsing url: ", err)
								}
								return nil, false
							}
						default:
							if i == 0 {
								reqHeaders.Add(header.Name, header.Value)
							} else {
								respHeaders.Add(header.Name, header.Value)
							}
						}
						if LOG_LEVEL >= DEBUG {
							log.Println(header.Name + ":" + header.Value)
						}
					}
				}

				if frame._type == DATA {
					if i == 0 {
						reqBody = append(reqBody, frame._data...)
					} else {
						respBody = append(respBody, frame._data...)
					}

					if LOG_LEVEL >= DEBUG {
						log.Printf("[PARSE] %s - DATA: %s\n", label, frame._data)
					}
				}

				if LOG_LEVEL >= TRACE {
					log.Println(SEP)
				}
			}

			// Wrap it up
			parsed.httpReq = http.Request{
				Method:        method,
				Host:          host,
				URL:           parsedUrl,
				Header:        reqHeaders,
				Body:          io.NopCloser(bytes.NewReader(reqBody)),
				ContentLength: int64(len(reqBody)),
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
			if LOG_LEVEL >= DEBUG {
				log.Println(SEP)
				log.Println("[PROCESS] Request: ", message.httpReq)
				log.Println("[PROCESS] Response: ", message.httpResp)
				log.Println("[PROCESS] Response time: ", message.responseMillis)
				log.Println("[PROCESS] Interval: ", message.interval)
				log.Printf("[PROCESS] Message is HTTP2: %v\n", message.isHttp2)

				body, err := io.ReadAll(message.httpReq.Body)
				if err == nil {
					log.Printf("[PROCESS] Request body %v:\n%s\n", message.httpReq.Body, body)
					message.httpReq.Body.Close()
					message.httpReq.Body = io.NopCloser(bytes.NewReader(body))
				}

				body, err = io.ReadAll(message.httpResp.Body)
				if err == nil {
					log.Printf("[PROCESS] Response body %v:\n%s\n", message.httpResp.Body, body)
					message.httpResp.Body.Close()
					message.httpResp.Body = io.NopCloser(bytes.NewReader(body))
				}
			}
			logger.SendHttpMessage(l, &message.httpResp, &message.httpReq, message.responseMillis, message.interval, nil)
		}
	}
}
