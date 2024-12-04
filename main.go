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
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const SEP string = "🗣️ 📢 🔥🔥🔥"
const DEBUG bool = false

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
	req      string
	httpReq  http.Request
	resp     string
	httpResp http.Response
	isHttp2  bool
}

type rawMessage struct {
	rawReq    []byte
	rawResp   []byte
	createdAt time.Time
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

	// Attach probes to OpenSSL executable.

	ex, err := link.OpenExecutable("/lib/x86_64-linux-gnu/libssl.so.3")
	if err != nil {
		log.Fatal("Opening OpenSSL executable:", err)
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

	isClient := len(os.Args) > 1 && os.Args[1] == "client"

	go process()

	log.Println("Waiting for any OpenSSL calls...")

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
					if DEBUG {
						log.Printf("[MAIN] Message %d closed for ingestion", id)
						log.Printf("[MAIN] Raw Request: [% x]\n", message.rawReq)
						log.Printf("[MAIN] Raw Response: [% x]\n", message.rawResp)
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
	id := binary.LittleEndian.Uint32(rec.RawSample[:4])
	raw := rec.RawSample[4:]

	if DEBUG {
		t := "RES"
		if isReq {
			t = "REQ"
		}
		log.Printf("[INGEST] TGID - %s: %d\n", t, id)
		log.Printf("[INGEST] RAW - %s: % x\n", t, raw)
	}

	if message, exists := messages[id]; !exists {
		m := new(rawMessage)
		m.createdAt = time.Now()

		if isReq {
			m.isHttp2 = len(raw) >= 24 && string(raw[:24]) == http2.ClientPreface
			if m.isHttp2 {
				raw = raw[24:]
			}
		}
		messages[id] = m
	} else {
		if message.isClosed {
			return
		}
		if len(message.rawReq) == 0 && isReq {
			messages[id].isHttp2 = len(raw) >= 24 && string(raw[:24]) == http2.ClientPreface
			if messages[id].isHttp2 {
				raw = raw[24:]
			}
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

	if DEBUG {
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
			if DEBUG {
				log.Println("parsing url: ", err)
			}
			return nil
		}

		// Request headers
		headers := parseHeaders(req[1], nil)
		host := headers.Get("Host")

		// Response
		firstLine = bytes.Fields(resp[0])

		// Status code
		status, err := strconv.Atoi(string(firstLine[1]))
		if err != nil {
			if DEBUG {
				log.Println("parsing status code: ", err)
			}
			return nil
		}

		// Response headers
		headers = parseHeaders(resp[1], nil)

		// Trailers
		if len(resp[2]) != 0 && headers.Get("Transfer-Encoding") == "chunked" && headers.Get("Trailer") != "" {
			lastChunkIndex := bytes.LastIndex(resp[2], append([]byte("0"), crlf...)) + 3
			headers = parseHeaders(resp[2][lastChunkIndex:], headers)
			resp[2] = resp[2][:lastChunkIndex]
		}

		if DEBUG {
			log.Printf("[PARSE] Request body: % x\n", req[2])
			log.Printf("[PARSE] Response body: % x\n", resp[2])
		}

		// Wraping it up
		parsed.httpReq = http.Request{
			Method: method,
			Host:   host,
			URL:    parsedUrl,
			Header: headers,
			Body:   io.NopCloser(bytes.NewReader(req[2])),
		}

		if parsedUrl.IsAbs() {
			parsed.httpReq.RequestURI = string(path)
		}

		parsed.httpResp = http.Response{
			StatusCode: status,
			Header:     headers,
			Body:       io.NopCloser(bytes.NewReader(resp[2])),
		}

		parsed.req = string(message.rawReq)
		parsed.resp = string(message.rawResp)
	} else {
		var req, resp string

		for _, frame := range toFrames(message.rawReq) {
			if DEBUG {
				log.Printf("[PARSE] REQ - RAW FRAME: % x", frame._raw)
				log.Printf("[PARSE] REQ - PARSED FRAME\n\tLength: %d [% x]\n\tType: % x\n\tFlag: % x\n\tStream ID: %d [% x]\n\tRaw Data: % x\n",
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

				if DEBUG {
					log.Println("[PARSE] REQ - HEADERS")
				}

				for _, header := range headers {
					joined := header.Name + ":" + header.Value + "\r\n"
					req += joined
					if DEBUG {
						log.Println(joined)
					}
				}
			}

			if frame._type == DATA {
				req += string(frame._data)
				if DEBUG {
					log.Printf("[PARSE] REQ - DATA: %s\n", frame._data)
				}
			}

			if DEBUG {
				log.Println(SEP)
			}
		}

		parsed.req = req

		for _, frame := range toFrames(message.rawResp) {
			if DEBUG {
				log.Printf("[PARSE] RES - RAW FRAME: % x", frame._raw)
				log.Printf("[PARSE] RES - PARSED FRAME\n\tLength: %d [% x]\n\tType: % x\n\tFlag: % x\n\tStream ID: %d [% x]\n\tRaw Data: % x\n",
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

				if DEBUG {
					log.Println("[PARSE] RES - HEADERS")
				}

				for _, header := range headers {
					joined := header.Name + ":" + header.Value + "\r\n"
					resp += joined
					if DEBUG {
						log.Println(joined)
					}
				}
			}

			if frame._type == DATA {
				resp += string(frame._data)
				if DEBUG {
					log.Printf("[PARSE] RES - DATA: %s\n", frame._data)
				}
			}

			if DEBUG {
				log.Println(SEP)
			}
		}

		parsed.resp = resp
	}

	if DEBUG {
		log.Printf("[PARSE] Parsed Message info <len(req), len(resp)>: %d, %d\n", len(parsed.req), len(parsed.resp))
	}

	if len(parsed.req) == 0 || len(parsed.resp) == 0 {
		return nil
	}

	return parsed
}

func process() {
	for {
		message := <-mc
		if message != nil {
			if !message.isHttp2 {
				log.Println("Message is HTTP1")

				log.Println(message.httpReq)
				body, err := io.ReadAll(message.httpReq.Body)
				if err == nil {
					bodys := "-"
					if len(body) != 0 {
						bodys = string(body)
					}
					log.Println("Request body: ", bodys)
					message.httpReq.Body.Close()
				}

				log.Println(message.httpResp)
				body, err = io.ReadAll(message.httpResp.Body)
				if err == nil {
					bodys := "-"
					if len(body) != 0 {
						bodys = string(body)
					}
					log.Println("Response body: ", bodys)
					message.httpResp.Body.Close()
				}
			} else {
				log.Println("Message is HTTP2")
				log.Printf("REQUEST %s\n%s\n", SEP, message.req)
				log.Printf("RESPONSE %s\n%s\n", SEP, message.resp)
			}
			log.Println(SEP)
		}
	}
}
