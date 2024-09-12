PROJECT_NAME=ebpf-logger

build:
	@rm ebpf-logger logger_bpfel.go logger_bpfeb.go  logger_bpfeb.o logger_bpfel.o
	@go generate
	@go build
	@sudo ./ebpf-logger
build-ebpf:
	@go generate
build-go:
	@go build
clean:
	@rm ebpf-logger logger_bpfel.go logger_bpfeb.go  logger_bpfeb.o logger_bpfel.o
