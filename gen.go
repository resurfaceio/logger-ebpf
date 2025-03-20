package main

//x86_64:generate go run github.com/cilium/ebpf/cmd/bpf2go -type trace_t -target amd64 logger logger.c -- -I /usr/include/x86_64-linux-gnu/

//aarch64:generate go run github.com/cilium/ebpf/cmd/bpf2go -type trace_t -target arm64 logger logger.c -- -I /usr/include/aarch64-linux-gnu/
