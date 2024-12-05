PROJECT_NAME=logger-ebpf

ifneq ($(wildcard ./.env),)
    include .env
	export
endif

run:
	sudo ./ebpf-logger
build: clean
	go generate
	go build
	@echo "== BUILD OK =="
build-ebpf:
	go generate
build-go:
	go build
headers:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clean:
	rm -f ebpf-logger logger_bpfel.go logger_bpfeb.go logger_bpfeb.o logger_bpfel.o logger_x86_bpfel.go logger_x86_bpfel.o
