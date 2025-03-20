package main

import (
	"errors"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type closer interface {
	Close() error
}

var err error

func earlyClose(closers *[]closer) {
	if err != nil {
		for _, c := range *closers {
			if err := c.Close(); err != nil {
				log.Println("error attempting to call close:", err)
			}
		}
	} else {
		log.Println("ebpf programs loaded successfully!")
	}
}

func load(exPath string, isClient bool) []closer {
	var closers []closer

	// Remove resource limits for kernels <5.11.
	//---------------------------------------------------------
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	//---------------------------------------------------------
	var objs loggerObjects
	if err = loadLoggerObjects(&objs, nil); err != nil {
		if DEBUG > 1 {
			var verr *ebpf.VerifierError
			if errors.As(err, &verr) {
				log.Printf("%+v\n", verr)
			}
		}
		log.Println("Loading eBPF objects:", err)
		return nil
	}
	closers = append(closers, &objs)
	defer earlyClose(&closers)

	//---------------------------------------------------------

	// Attach kprobes and kretprobes

	if !isClient {
		kAccept, err := link.Kprobe("sys_accept", objs.EntrySysAccept, nil)
		if err != nil {
			log.Panicln("Attaching kprobe:", err)
		}
		closers = append(closers, kAccept)

		kretAccept, err := link.Kretprobe("sys_accept", objs.RetSysAccept, nil)
		if err != nil {
			log.Panicln("Attaching kretprobe:", err)
		}
		closers = append(closers, kretAccept)

		kAccept4, err := link.Kprobe("sys_accept4", objs.EntrySysAccept4, nil)
		if err != nil {
			log.Panicln("Attaching kprobe:", err)
		}
		closers = append(closers, kAccept4)

		kretAccept4, err := link.Kretprobe("sys_accept4", objs.RetSysAccept4, nil)
		if err != nil {
			log.Panicln("Attaching kretprobe:", err)
		}
		closers = append(closers, kretAccept4)
	}

	//---------------------------------------------------------

	// Attach uprobes and uretprobes to executable.

	ex, err := link.OpenExecutable(exPath)
	if err != nil {
		log.Panicln("Opening executable:", err)
	}

	// Define links between OpenSSL functions and the corresponding BPF functions in logger.c

	// SSL_read
	entryRead, err := ex.Uprobe("SSL_read", objs.EntrySslRead, nil)
	if err != nil {
		log.Panicln("Attaching uprobe:", err)
	}
	closers = append(closers, entryRead)

	exitRead, err := ex.Uretprobe("SSL_read", objs.RetSslRead, nil)
	if err != nil {
		log.Panicln("Attaching uretprobe:", err)
	}
	closers = append(closers, exitRead)

	// SSL_write
	entryWrite, err := ex.Uprobe("SSL_write", objs.EntrySslWrite, nil)
	if err != nil {
		log.Panicln("Attaching uprobe:", err)
	}
	closers = append(closers, entryWrite)

	exitWrite, err := ex.Uretprobe("SSL_write", objs.RetSslWrite, nil)
	if err != nil {
		log.Panicln("Attaching uretprobe:", err)
	}
	closers = append(closers, exitWrite)

	if isClient {
		// SSL_connect
		entryConnect, err := ex.Uprobe("SSL_connect", objs.EntrySslConnect, nil)
		if err != nil {
			log.Panicln("Attaching uprobe:", err)
		}
		closers = append(closers, entryConnect)

		exitConnect, err := ex.Uretprobe("SSL_connect", objs.RetSslConnect, nil)
		if err != nil {
			log.Panicln("Attaching uretprobe:", err)
		}
		closers = append(closers, exitConnect)
	} else {
		// SSL_accept
		entryAccept, err := ex.Uprobe("SSL_accept", objs.EntrySslAccept, nil)
		if err != nil {
			log.Panicln("Attaching uprobe:", err)
		}
		closers = append(closers, entryAccept)

		exitAccept, err := ex.Uretprobe("SSL_accept", objs.RetSslAccept, nil)
		if err != nil {
			log.Panicln("Attaching uretprobe:", err)
		}
		closers = append(closers, exitAccept)
	}

	// SSL_shutdown
	entryShutdown, err := ex.Uprobe("SSL_shutdown", objs.EntrySslShutdown, nil)
	if err != nil {
		log.Panicln("Attaching uprobe:", err)
	}
	closers = append(closers, entryShutdown)

	exitShutdown, err := ex.Uretprobe("SSL_shutdown", objs.RetSslShutdown, nil)
	if err != nil {
		log.Panicln("Attaching uretprobe:", err)
	}
	closers = append(closers, exitShutdown)

	return closers
}
