package main

import (
	"log"
	"fmt"
	"time"
	"os"
	"os/signal"

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

	// Attach Hello to the accept4 system call.
	opts := &link.KprobeOptions {}
	link, err := link.Kprobe("__sys_read", objs.BPF_KSYSCALL, opts)
	if err != nil {
		log.Fatal("Attaching kprobe:", err)
	}
	info, err := link.Info()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(*info)
	defer link.Close()

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	type Output interface {
		fd() int
		buf() string
	}

	for {
		select {
		case <-tick:
			var valueOut Output;
			err := objs.ActiveReadArgsMap.Lookup(uint32(0), valueOut);
			if err != nil {
				log.Fatal("Map lookup:", err);
			}
			log.Printf("%d system calls made...");
		case <-stop:
			log.Print("Received signal, exiting...");
			return;
		}
	}
}
