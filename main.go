package main

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const MAX_BYTES_READ int = 500
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

	// Attach probes to the read system call.
	entrylink, err := link.Kprobe("sys_read", objs.EntryRead, nil)
	if err != nil {
		log.Fatal("Attaching kprobe:", err)
	}
	defer entrylink.Close()

	retlink, err := link.Kretprobe("sys_read", objs.RetRead, nil)
	if err != nil {
		log.Fatal("Attaching kretprobe:", err)
	}
	defer retlink.Close()

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	type Out struct {
		Fd   uint32
		Data [MAX_BYTES_READ]byte
	}

	var debugkey string

	for {
		select {
		case <-tick:
			var (
				key     uint32
				value   Out
				entries = objs.ActiveReadArgsMap.Iterate()
			)
			values := make(map[uint32]Out)

			for entries.Next(&key, &value) {
				values[key] = value
			}

			if err := entries.Err(); err != nil {
				log.Fatal("Iterator encountered an error:", err)
			}

			for k, v := range values {
				if k == 0 {
					debugkey = "KPROBE: count"
				} else if k == 1 {
					debugkey = "KRETPROBE: error"
				} else if k == 2 {
					debugkey = "KRETPROBE: read OK"
				} else {
					debugkey = "UNKNOWN"
				}
				log.Printf("[DEBUG %s]\nkey: %d \nvalue:\n - fd: %d\n - message:\n\"%s\"\n%s\n", debugkey, k, v.Fd, v.Data, SEP)
			}
		case <-stop:
			log.Print("Received signal, exiting...")
			return
		}
	}
}
