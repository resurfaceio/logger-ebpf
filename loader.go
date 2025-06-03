// © 2025 Graylog, Inc.

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

func load(exPath string, isClient bool) []closer {
	var closers []closer

	// Remove resource limits for kernels <5.11.
	//---------------------------------------------------------
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("error: Removing memlock:", err)
		log.Fatal("Unable to load eBPF programs. Please make sure that you have the right permissions to make bpf() calls.")
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	//---------------------------------------------------------
	var err error
	var objs loggerObjects
	if err = loadLoggerObjects(&objs, nil); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Printf("%+v\n", verr)
		}
		log.Println("error: Loading eBPF objects:", err)
		return nil
	}
	closers = append(closers, &objs)
	defer func(closers *[]closer) {
		if err != nil {
			for _, c := range *closers {
				if err := c.Close(); err != nil {
					log.Println("error attempting to call close:", err)
				}
			}
		} else {
			log.Println("eBPF programs loaded successfully.")
		}
	}(&closers)

	//---------------------------------------------------------

	// Attach uprobes and uretprobes to executable.

	ex, err := link.OpenExecutable(exPath)
	if err != nil {
		log.Panicln("error: Opening executable:", err)
	}

	// Define links between OpenSSL functions and the corresponding BPF functions in logger.c

	// SSL_read
	entryRead, err := ex.Uprobe("SSL_read", objs.EntrySslRead, nil)
	if err != nil {
		log.Panicln("error: Attaching SSL_read uprobe:", err)
	}
	closers = append(closers, entryRead)

	exitRead, err := ex.Uretprobe("SSL_read", objs.RetSslRead, nil)
	if err != nil {
		log.Panicln("error: Attaching SSL_read uretprobe:", err)
	}
	closers = append(closers, exitRead)

	// SSL_write
	entryWrite, err := ex.Uprobe("SSL_write", objs.EntrySslWrite, nil)
	if err != nil {
		log.Panicln("error: Attaching SSL_write uprobe:", err)
	}
	closers = append(closers, entryWrite)

	exitWrite, err := ex.Uretprobe("SSL_write", objs.RetSslWrite, nil)
	if err != nil {
		log.Panicln("error: Attaching SSL_write uretprobe:", err)
	}
	closers = append(closers, exitWrite)

	if isClient {
		// SSL_connect
		entryConnect, err := ex.Uprobe("SSL_connect", objs.EntrySslConnect, nil)
		if err != nil {
			log.Panicln("error: Attaching SSL_connect uprobe:", err)
		}
		closers = append(closers, entryConnect)

		exitConnect, err := ex.Uretprobe("SSL_connect", objs.RetSslConnect, nil)
		if err != nil {
			log.Panicln("error: Attaching SSL_connect uretprobe:", err)
		}
		closers = append(closers, exitConnect)
	} else {
		// SSL_accept
		entryAccept, err := ex.Uprobe("SSL_accept", objs.EntrySslAccept, nil)
		if err != nil {
			log.Panicln("error: Attaching SSL_accept uprobe:", err)
		}
		closers = append(closers, entryAccept)

		exitAccept, err := ex.Uretprobe("SSL_accept", objs.RetSslAccept, nil)
		if err != nil {
			log.Panicln("error: Attaching SSL_accept uretprobe:", err)
		}
		closers = append(closers, exitAccept)

		// SSL_set_accept_state + SSL_do_handshake
		entrySetAcceptState, err := ex.Uprobe("SSL_set_accept_state", objs.EntrySslAccept, nil)
		if err != nil {
			log.Panicln("error: Attaching SSL_set_accept_state uprobe:", err)
		}
		closers = append(closers, entrySetAcceptState)

		exitHandshake, err := ex.Uretprobe("SSL_do_handshake", objs.RetSslDoHandshake, nil)
		if err != nil {
			log.Panicln("error: Attaching SSL_accept uretprobe:", err)
		}
		closers = append(closers, exitHandshake)
	}

	// SSL_shutdown
	entryShutdown, err := ex.Uprobe("SSL_shutdown", objs.EntrySslShutdown, nil)
	if err != nil {
		log.Panicln("error: Attaching SSL_shutdown uprobe:", err)
	}
	closers = append(closers, entryShutdown)

	return closers
}
