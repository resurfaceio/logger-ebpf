package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 logger logger.c -- -I /usr/include/x86_64-linux-gnu/
