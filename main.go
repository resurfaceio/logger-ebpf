package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

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

	// Attach Hello to the read system call.
	// opts := &link.KprobeOptions{}
	l, err := link.Kprobe("sys_read", objs.SyscallProbeEntryRead, nil)
	if err != nil {
		log.Fatal("Attaching kprobe:", err)
	}
	info, err := l.Info()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("- Link [kprobe/sys_read]:", *info)
	defer l.Close()

	l2, err := link.Kretprobe("sys_read", objs.SyscallProbeReturnRead, nil)
	if err != nil {
		log.Fatal("Attaching kretprobe:", err)
	}
	info, err = l2.Info()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("- Link [kretprobe/sys_read]:", *info)
	defer l2.Close()

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	// type Output interface {
	// 	fd() int
	// 	buf() string
	// }

	for {
		select {
		case <-tick:
			var (
				key   uint32
				value string
				// entries = objs.EntryStashMap.Iterate()
				entries = objs.ActiveReadArgsMap.Iterate()
			)
			values := make(map[uint32]string)

			// ok := entries.Next(&key, &value)
			// log.Print(ok)

			for entries.Next(&key, &value) {
				values[key] = value
			}

			if err := entries.Err(); err != nil {
				log.Fatal("Iterator encountered an error:", err)
			}

			for k, v := range values {
				log.Printf("key: %d, value: %s\n", k, v)
			}

			// var valueOut string
			// err := objs.ActiveReadArgsMap.Lookup(uint32(0), &valueOut)
			// if err != nil {
			// 	log.Print("Map lookup:", err)
			// }
			// if valueOut != "" {
			// 	log.Print(valueOut)
			// }
			// return
			// log.Printf("%d system calls made...")
		case <-stop:
			log.Print("Received signal, exiting...")
			return
		}
	}
}
