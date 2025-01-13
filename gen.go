package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type trace_t -target amd64 logger logger.c -- -I /usr/include/x86_64-linux-gnu/
