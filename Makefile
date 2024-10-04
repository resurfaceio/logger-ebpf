PROJECT_NAME=logger-ebpf

run:
	sudo ./ebpf-logger
build: clean
	go generate
	go build
build-ebpf:
	go generate
build-go:
	go build
clean:
	rm -f ebpf-logger logger_bpfel.go logger_bpfeb.go logger_bpfeb.o logger_bpfel.o