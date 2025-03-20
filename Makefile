PROJECT_NAME=logger-ebpf

ifneq ($(wildcard ./.env),)
    include .env
	export
endif

ifeq ($(nosudo),)
	sudo=sudo 
endif

run:
	@echo USAGE_LOGGERS_URL=${USAGE_LOGGERS_URL}
	@echo USAGE_LOGGERS_RULES=${USAGE_LOGGERS_RULES}
	@echo USAGE_LOGGERS_EBPF_ROLE=${USAGE_LOGGERS_EBPF_ROLE}
	@echo USAGE_LOGGERS_EBPF_EXPATH=${USAGE_LOGGERS_EBPF_EXPATH}
	$(sudo) ./ebpf-logger

skeleton: clean
	go generate
build: skeleton
	go build
	@echo "== BUILD OK =="
headers:
	$(sudo) bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

dotenv:
	cp --update=none .env.example .env
clean:
	rm -f ebpf-logger logger_bpfel.go logger_bpfeb.go logger_bpfeb.o logger_bpfel.o logger_x86_bpfel.go logger_x86_bpfel.o logger_arm64_bpfel.go logger_arm64_bpfel.o
