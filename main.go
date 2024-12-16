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

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	logger "github.com/resurfaceio/logger-go/v3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const SEP string = "🗣️ 📢 🔥🔥🔥"
const DEBUG int = 1

const (
	DATA byte = iota
	HEADERS
	PRIORITY
	RST_STREAM
	SETTINGS
	PUSH_PROMISE
	PING
	GOAWAY
	WINDOW_UPDATE
	CONTINUATION
	ALTSVC
	ORIGIN
)

type parsedMessage struct {
	httpReq        http.Request
	httpResp       http.Response
	isHttp2        bool
	responseMillis int64
	interval       int64
}

type rawMessage struct {
	rawReq    []byte
	rawResp   []byte
	createdAt time.Time
	reqTime   time.Time
	respTime  time.Time
	isHttp2   bool
	isClosed  bool
}

type h2frame struct {
	_len       [3]byte
	_lend      uint32
	_type      byte
	_flag      byte
	_streamID  [4]byte
	_streamIDd uint32
	_data      []byte
	_empty     bool
	_raw       []byte
}

var crlf []byte = []byte("\r\n")

var messages map[uint32]*rawMessage
var mc chan *parsedMessage
var l *logger.HttpLogger

func toh2frame(barray []byte, offset int) (frame h2frame, nextIndex int) {
	//log.Println("offset: ", offset)
	if offset+3 > len(barray) {
		nextIndex = -1
		frame._empty = true
		return
	}
	copy(frame._len[:], barray[offset:3+offset])

	tmp := make([]byte, 4)
	copy(tmp[1:], frame._len[:])
	frame._lend = binary.BigEndian.Uint32(tmp)
	//log.Println("lend: ", frame._lend)

	nextIndex = 9 + offset + int(frame._lend)
	if nextIndex > len(barray) {
		nextIndex = -1
		frame._empty = true
		return
	}

	frame._type = barray[3+offset]

	if frame._type == SETTINGS {
		// nothing
	}

	frame._flag = barray[4+offset]

	copy(frame._streamID[:], barray[5+offset:9+offset])

	copy(tmp[:], frame._streamID[:])
	frame._streamIDd = binary.BigEndian.Uint32(tmp)

	frame._empty = (frame._lend+uint32(frame._type)+uint32(frame._flag)+frame._streamIDd == 0)
	if !frame._empty {
		frame._data = make([]byte, frame._lend)
		copy(frame._data, barray[9+offset:nextIndex])

		frame._raw = make([]byte, nextIndex-offset)
		copy(frame._raw, barray[offset:nextIndex])
	}

	return
}

func toFrames(frameBytes []byte) (frames []h2frame) {
	var frame h2frame
	var offset int = 0
	// for {
	for offset < len(frameBytes) {
		frame, offset = toh2frame(frameBytes, offset)
		if offset == -1 {
			break
		}
		if !frame._empty {
			frames = append(frames, frame)
		}
	}

	return
}

func main() {
	defer log.Println("All done. Bye!")

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	//--------------------------------------------

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs loggerObjects
	if err := loadLoggerObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	//---------------------------------------------------------

	// Attach probes to executable.

	exPath, exists := os.LookupEnv("USAGE_LOGGERS_EBPF_EXPATH")
	if !exists {
		log.Fatalln("USAGE_LOGGERS_EBPF_EXPATH not set")
	}

	if DEBUG > 1 {
		log.Println("executable: ", exPath)
	}

	ex, err := link.OpenExecutable(exPath)
	if err != nil {
		log.Fatal("Opening executable:", err)
	}

	// Define links between OpenSSL functions and the corresponding BPF functions in logger.c

	// SSL_read
	entryRead, err := ex.Uprobe("SSL_read", objs.EntrySslRead, nil)
	if err != nil {
		log.Fatal("Attaching uprobe:", err)
	}
	defer entryRead.Close()

	exitRead, err := ex.Uretprobe("SSL_read", objs.RetSslRead, nil)
	if err != nil {
		log.Fatal("Attaching uretprobe:", err)
	}
	defer exitRead.Close()

	// SSL_write
	entryWrite, err := ex.Uprobe("SSL_write", objs.EntrySslWrite, nil)
	if err != nil {
		log.Fatal("Attaching uprobe:", err)
	}
	defer entryWrite.Close()

	exitWrite, err := ex.Uretprobe("SSL_write", objs.RetSslWrite, nil)
	if err != nil {
		log.Fatal("Attaching uretprobe:", err)
	}
	defer exitWrite.Close()

	//---------------------------------------------------------

	// Define structures to receive data

	readsReader, err := ringbuf.NewReader(objs.Reads)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer readsReader.Close()

	writesReader, err := ringbuf.NewReader(objs.Writes)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer writesReader.Close()

	r := make(chan ringbuf.Record)
	w := make(chan ringbuf.Record)
	messages = make(map[uint32]*rawMessage)
	mc = make(chan *parsedMessage)

	go readRing(readsReader, &r, "reads")
	go readRing(writesReader, &w, "writes")

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	//---------------------------------------------------------

	isClient := os.Getenv("USAGE_LOGGERS_EBPF_ROLE") == "client"

	opts := logger.Options{Rules: os.Getenv("USAGE_LOGGERS_RULES")}
	l, err = logger.NewHttpLogger(opts)
	if err != nil {
		log.Fatalln("initializing logger: ", err)
	}
	if !l.Enabled() {
		log.Println("logger is not enabled")
		return
	}
	if DEBUG > 0 {
		log.Println("logger is initialized")
		if DEBUG > 1 {
			log.Println("  url:   ", os.Getenv("USAGE_LOGGERS_URL"))
			log.Println("  rules: ", opts.Rules)
		}
		log.Println("Waiting for any OpenSSL calls...")
	}

	go process()

	for {
		select {
		case <-stop:
			log.Println("Received signal, exiting...")

			if err := readsReader.Flush(); err != nil {
				log.Fatalf("flushing ringbuf reads reader: %s", err)
			}
			// readRingOnce(readsReader, &r, "reads")
			if err := readsReader.Close(); err != nil {
				log.Fatalf("closing ringbuf reads reader: %s", err)
			}

			if err := writesReader.Flush(); err != nil {
				log.Fatalf("flushing ringbuf writes reader: %s", err)
			}
			// readRingOnce(writesReader, &w, "writes")
			if err := writesReader.Close(); err != nil {
				log.Fatalf("closing ringbuf writes reader: %s", err)
			}
			return

		case record := <-r:
			ingest(record, !isClient)
		case record := <-w:
			ingest(record, isClient)
		default:
			for id, message := range messages {
				if !message.isClosed && time.Since(message.createdAt) > 3*time.Second && len(message.rawReq) != 0 && len(message.rawResp) != 0 {
					message.isClosed = true
					if DEBUG > 1 {
						log.Printf("[MAIN] Message %d closed for ingestion", id)
						if DEBUG > 2 {
							log.Printf("[MAIN] Raw Request: [% x]\n", message.rawReq)
							log.Printf("[MAIN] Raw Response: [% x]\n", message.rawResp)
						}
					}
					mc <- parse(message)
				}
			}
			// time.Sleep(2 * time.Second)
		}
	}
}

func readRing(reader *ringbuf.Reader, c *chan ringbuf.Record, name string) {
	var received ringbuf.Record
	for {
		if err := reader.ReadInto(&received); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Printf("closing %s channel...\n", name)
				close(*c)
				return
			}
			log.Printf("reading from %s reader: %s", name, err)
			continue
		}
		*c <- received
	}
}

// func readRingOnce(reader *ringbuf.Reader, c *chan ringbuf.Record, name string) {
// 	log.Println("TO READ RING ONCE")
// 	var received ringbuf.Record
// 	if err := reader.ReadInto(&received); err != nil {
// 		if errors.Is(err, ringbuf.ErrClosed) {
// 			log.Printf("closing %s channel...\n", name)
// 			close(*c)
// 			return
// 		}
// 		log.Printf("reading from %s reader: %s", name, err)
// 		log.Println("WILL RETURN")
// 		return
// 	}
// 	*c <- received
// }

func ingest(rec ringbuf.Record, isReq bool) {
	if len(rec.RawSample) < 4 {
		return
	}
	now := time.Now()
	id := binary.LittleEndian.Uint32(rec.RawSample[:4])
	raw := rec.RawSample[4:]

	if DEBUG > 2 {
		t := "RES"
		if isReq {
			t = "REQ"
		}
		log.Printf("[INGEST] TGID - %s: %d\n", t, id)
		log.Printf("[INGEST] RAW - %s: % x\n", t, raw)
	}

	if message, exists := messages[id]; !exists {
		m := new(rawMessage)
		m.createdAt = now

		if isReq {
			m.reqTime = now
			m.isHttp2 = len(raw) >= 24 && string(raw[:24]) == http2.ClientPreface
			if m.isHttp2 {
				raw = raw[24:]
			}
		} else {
			m.respTime = now
		}
		messages[id] = m
	} else {
		if message.isClosed {
			return
		}
		if len(message.rawReq) == 0 && isReq {
			messages[id].reqTime = now
			messages[id].isHttp2 = len(raw) >= 24 && string(raw[:24]) == http2.ClientPreface
			if messages[id].isHttp2 {
				raw = raw[24:]
			}
		} else if len(message.rawResp) == 0 && !isReq {
			messages[id].respTime = now
		}
	}

	message := messages[id]

	if isReq {
		message.rawReq = append(message.rawReq, raw...)
	} else {
		message.rawResp = append(message.rawResp, raw...)
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

func parse(message *rawMessage) *parsedMessage {
	parsed := new(parsedMessage)
	parsed.isHttp2 = message.isHttp2

	if DEBUG > 1 {
		log.Printf("[PARSE] Raw Message info <len(req), len(resp), isHttp2>: %d, %d, %v\n", len(message.rawReq), len(message.rawResp), message.isHttp2)
	}

	if !message.isHttp2 {
		var req [3][]byte
		var resp [3][]byte

		// Slice first line, headers, body+trailers
		copy(req[:2], bytes.SplitN(message.rawReq, crlf, 2))
		copy(resp[:2], bytes.SplitN(message.rawResp, crlf, 2))

		copy(req[1:], bytes.SplitN(req[1], append(crlf, crlf...), 2))
		copy(resp[1:], bytes.SplitN(resp[1], append(crlf, crlf...), 2))

		// Request
		firstLine := bytes.Fields(req[0])

		// Method
		method := string(firstLine[0])

		// URL
		path := firstLine[1]
		if !bytes.Contains(path, []byte("://")) && !bytes.HasPrefix(path, []byte("/")) {
			path = append([]byte("/"), path...)
		}
		parsedUrl, err := url.Parse(string(path))
		if err != nil {
			if DEBUG > 0 {
				log.Println("parsing url: ", err)
			}
			return nil
		}

		// Request headers
		reqHeaders := parseHeaders(req[1], nil)
		host := reqHeaders.Get("Host")

		// Response
		firstLine = bytes.Fields(resp[0])

		// Status code
		status, err := strconv.Atoi(string(firstLine[1]))
		if err != nil {
			if DEBUG > 0 {
				log.Println("parsing status code: ", err)
			}
			return nil
		}

		// Response headers
		respHeaders := parseHeaders(resp[1], nil)

		// Trailers
		if len(resp[2]) != 0 && respHeaders.Get("Transfer-Encoding") == "chunked" && respHeaders.Get("Trailer") != "" {
			lastChunkIndex := bytes.LastIndex(resp[2], append([]byte("0"), crlf...)) + 3
			respHeaders = parseHeaders(resp[2][lastChunkIndex:], respHeaders)
			resp[2] = resp[2][:lastChunkIndex]
		}

		if DEBUG > 1 {
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
				if DEBUG > 2 {
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
					decoder := hpack.NewDecoder(2048, nil)
					headers, err := decoder.DecodeFull(frame._data)
					if err != nil {
						log.Println("decoding headers: ", err)
						continue
					}

					if DEBUG > 1 {
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
								if DEBUG > 0 {
									log.Println("decoding path: ", err)
								}
								return nil
							}
							parsedUrl.Path = pathQuery.Path
							parsedUrl.RawQuery = pathQuery.RawQuery
						case ":status":
							status, err = strconv.Atoi(header.Value)
							if err != nil {
								if DEBUG > 0 {
									log.Println("parsing url: ", err)
								}
								return nil
							}
						default:
							if i == 0 {
								reqHeaders.Add(header.Name, header.Value)
							} else {
								respHeaders.Add(header.Name, header.Value)
							}
						}
						if DEBUG > 1 {
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

					if DEBUG > 1 {
						log.Printf("[PARSE] %s - DATA: %s\n", label, frame._data)
					}
				}

				if DEBUG > 1 {
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

	return parsed
}

func process() {
	for {
		message := <-mc
		if message != nil {
			if DEBUG > 0 {
				log.Println(SEP)
				log.Println("Request: ", message.httpReq)
				log.Println("Response: ", message.httpResp)
				log.Println("Response time: ", message.responseMillis)
				log.Println("Interval: ", message.interval)
				log.Printf("Message is HTTP2: %v\n", message.isHttp2)

				body, err := io.ReadAll(message.httpReq.Body)
				if err == nil {
					log.Printf("Request body %v:\n%s\n", message.httpReq.Body, body)
					message.httpReq.Body.Close()
					message.httpReq.Body = io.NopCloser(bytes.NewReader(body))
				}

				body, err = io.ReadAll(message.httpResp.Body)
				if err == nil {
					log.Printf("Response body %v:\n%s\n", message.httpResp.Body, body)
					message.httpResp.Body.Close()
					message.httpResp.Body = io.NopCloser(bytes.NewReader(body))
				}
			}
			logger.SendHttpMessage(l, &message.httpResp, &message.httpReq, message.responseMillis, message.interval, nil)
		}
	}
}
