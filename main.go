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
	if nextIndex >= len(barray) {
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
	entryRead, err := ex.Uprobe("SSL_read", objs.EntrySsl, nil)
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
	entryWrite, err := ex.Uprobe("SSL_write", objs.EntrySsl, nil)
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

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	go func() {
		<-stop

		if err := readsReader.Close(); err != nil {
			log.Fatalf("closing ringbuf reads reader: %s", err)
		}

		if err := writesReader.Close(); err != nil {
			log.Fatalf("closing ringbuf writes reader: %s", err)
		}
	}()

	//---------------------------------------------------------

	log.Println("Waiting for any OpenSSL calls...")

	for {
		readsReceived, err := readsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reads reader: %s", err)
			continue
		}

		writesReceived, err := writesReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from writes reader: %s", err)
			continue
		}

		log.Println(SEP, "NEW BATCH - SSL_READ", SEP)
		if DEBUG {
			log.Printf("SSL_READ [FULL RAW PAYLOAD]: % x", readsReceived.RawSample)
			log.Printf("SSL_READ [FULL ASCII PAYLOAD]: %s", readsReceived.RawSample)
		}
		for _, rFrame := range toFrames(readsReceived.RawSample) {
			log.Println(SEP)
			if DEBUG {
				log.Printf("SSL_READ [RAW FRAME]: % x", rFrame._raw)
			}
			log.Printf("SSL_READ [FRAME]:\n\tLength: %d [% x]\n\tType: % x\n\tFlag: % x\n\tStream ID: %d [% x]\n\tData: % x\n",
				rFrame._lend,
				rFrame._len,
				rFrame._type,
				rFrame._flag,
				rFrame._streamIDd,
				rFrame._streamID,
				rFrame._data)
		}

		log.Println(SEP, "NEW BATCH - SSL_WRITE", SEP)
		if DEBUG {
			log.Printf("SSL_WRITE [FULL RAW PAYLOAD]: % x", writesReceived.RawSample)
			log.Printf("SSL_WRITE [FULL ASCII PAYLOAD]: %s", writesReceived.RawSample)
		}
		for _, wFrame := range toFrames(writesReceived.RawSample) {
			log.Println(SEP)
			if DEBUG {
				log.Printf("SSL_WRITE [RAW FRAME]: % x", string(wFrame._raw))
			}
			log.Printf("SSL_WRITE [FRAME]:\n\tLength: %d [% x]\n\tType: % x\n\tFlag: % x\n\tStream ID: %d [% x]\n\tData: % x\n",
				wFrame._lend,
				wFrame._len,
				wFrame._type,
				wFrame._flag,
				wFrame._streamIDd,
				wFrame._streamID,
				wFrame._data)

		}
		log.Println(SEP)
	}
}
