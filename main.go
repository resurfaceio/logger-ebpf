package main

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const MAX_BYTES int = 500
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

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	type Out struct {
		Id  uint32
		Buf [MAX_BYTES]byte
	}

	log.Println("Waiting for any OpenSSL calls...")

	for {
		select {
		case <-tick:
			var key uint32 = 2
			var value Out

			err = objs.SslDataMap.LookupAndDelete(key, &value)
			if err != nil {
				continue
			}

			if value.Id == 0 {
				continue
			}

			log.Printf("[DEBUG URETPROBE: OK]\nkey: %d \nvalue:\n - tid: %d\n - message:\n\"%s\"\n%s\n", 2, value.Id, value.Buf, SEP)
		case <-stop:
			log.Print("Received signal, exiting...")
			return
		}
	}
}
