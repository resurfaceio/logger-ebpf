package main

import (
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// const MAX_BYTES int = 500
const SEP string = "🗣️ 📢 🔥🔥🔥"
const DEBUG bool = true

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

	readers := map[string]*ringbuf.Reader{"READ": readsReader, "WRITE": writesReader}
	rw := make([]string, 0, len(readers))
	for k := range readers {
		rw = append(rw, k)
	}

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	go func() {
		<-stop

		for rtype, reader := range readers {
			if err := reader.Close(); err != nil {
				log.Fatalf("closing ringbuf \"%s\" reader: %s", rtype, err)
			}
		}
	}()

	//---------------------------------------------------------

	// var received [2]ringbuf.Record

	// isHttp2 := false
	isClient := len(os.Args) > 1 && os.Args[1] == "client"

	if isClient {
		rw[0], rw[1] = rw[1], rw[0]
		log.Println("Logger enabled in CLIENT mode")
	}

	log.Println("Waiting for any OpenSSL calls...")

	for {
		for _, key := range rw {
			// for i, key := range rw {
			reader := readers[key]

			received, err := reader.Read()
			// record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting..")
					return
				}
				log.Printf("reading from %s reader: %s", key, err)
				continue
			}
			// received[i] = record

			var raw []byte

			if len(received.RawSample) >= 24 && string(received.RawSample[:24]) == http2.ClientPreface {
				raw = received.RawSample[24:]
				log.Println("RECEIVED HTTP2 MESSAGE")
			} else {
				raw = received.RawSample
				// log.Printf("SSL_%s [FULL ASCII PAYLOAD]: %s", key, received.RawSample)
				// continue
			}

			log.Printf("%sNEW BATCH - SSL_%s %s", "", key, SEP)
			if DEBUG {
				log.Printf("SSL_%s [FULL RAW PAYLOAD]: % x", key, received.RawSample)
				// log.Printf("SSL_%s [FULL ASCII PAYLOAD]: %s", key, received.RawSample)
			}

			for _, frame := range toFrames(raw) {
				if DEBUG {
					log.Printf("SSL_%s [RAW FRAME]: % x", key, frame._raw)
					log.Printf("SSL_%s [FRAME]\n\tLength: %d [% x]\n\tType: % x\n\tFlag: % x\n\tStream ID: %d [% x]\n\tRaw Data: % x\n",
						key,
						frame._lend,
						frame._len,
						frame._type,
						frame._flag,
						frame._streamIDd,
						frame._streamID,
						frame._data,
					)
				}

				if frame._type == DATA {
					log.Printf("DATA: %s\n", frame._data)
				}

				if frame._type == HEADERS {
					decoder := hpack.NewDecoder(2048, nil)
					headers, err := decoder.DecodeFull(frame._data)
					if err != nil {
						log.Println("decoding headers: ", err)
						continue
					}
					log.Println("HEADERS:")
					for _, header := range headers {
						log.Printf("\t%s\n", header.Name+":"+header.Value)
					}
				}

				if DEBUG {
					log.Println(SEP)
				}
			}
		}
	}
}
