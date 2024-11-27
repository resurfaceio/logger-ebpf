package main

import (
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
		log.Fatal("Opening executable:", err)
	}

	entrylinkr, err := ex.Uprobe("SSL_read", objs.EntrySsl, nil)
	if err != nil {
		log.Fatal("Attaching uprobe:", err)
	}
	defer entrylinkr.Close()

	entrylinkw, err := ex.Uprobe("SSL_write", objs.EntrySsl, nil)
	if err != nil {
		log.Fatal("Attaching uprobe:", err)
	}
	defer entrylinkw.Close()

	retlinkr, err := ex.Uretprobe("SSL_read", objs.RetSslRead, nil)
	if err != nil {
		log.Fatal("Attaching kretprobe:", err)
	}
	defer retlinkr.Close()

	retlinkw, err := ex.Uretprobe("SSL_write", objs.RetSslWrite, nil)
	if err != nil {
		log.Fatal("Attaching kretprobe:", err)
	}
	defer retlinkw.Close()

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	// var incoming loggerDataT

	log.Println("Waiting for any OpenSSL calls...")

	rr, err := ringbuf.NewReader(objs.Reads)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rr.Close()

	wr, err := ringbuf.NewReader(objs.Writes)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer wr.Close()

	go func() {
		<-stop

		if err := rr.Close(); err != nil {
			log.Fatalf("closing ringbuf reads reader: %s", err)
		}

		if err := wr.Close(); err != nil {
			log.Fatalf("closing ringbuf writes reader: %s", err)
		}
	}()

	for {
		receivedr, err := rr.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		receivedw, err := rr.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// var key, val uint32
		// key = 1
		// err = objs.IdMap.LookupAndDelete(&key, &val)
		// if err != nil {
		// 	log.Printf("map lookup: %s", err)
		// 	continue
		// }

		// log.Println(val)

		// log.Println(received.RawSample)
		// log.Println(binary.LittleEndian.Uint32(received.RawSample[:4]))
		log.Printf("SSL_READ: %s\n", string(receivedr.RawSample[4:]))
		log.Printf("SSL_WRITE: %s\n", string(receivedw.RawSample[4:]))

		// if err := binary.Read(bytes.NewBuffer(received.RawSample[128:]), binary.LittleEndian, &incoming); err != nil {
		// 	log.Printf("parsing ringbuf event: %s", err)
		// 	continue
		// }

		// log.Printf("[DEBUG URETPROBE: OK]\nkey: %d \nvalue:\n - tid: %d\n - message:\n\"%s\"\n%s\n", 2, incoming.Id, incoming.Data, SEP)
	}
}
