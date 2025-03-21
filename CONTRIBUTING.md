# Contributing to logger-ebpf

## Configuring Development Environment

Start with latest Ubuntu Noble (24.04.1 or later) on Intel x86 (64-bit) or ARM64 (64-bit)

Install required Go version (1.24.0):
```bash
cd /opt
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
tar -xzf go1.24.0.linux-amd64.tar.gz
export PATH="/opt/go/bin:$PATH"
go version
# 👆 should be 1.24.0
```

Install required packages:
```bash
sudo apt install clang git libbpf-dev make
```

Add required soft link:
```bash
sudo ln -s /usr/bin/llvm-strip-18 /usr/bin/llvm-strip
```

## Running Locally

### Set up environment

```bash
cd $HOME
git clone https://github.com/resurfaceio/logger-ebpf.git
cd logger-ebpf
make headers
make dotenv
```

#### Environment variables
The variables used by `logger-ebpf` are:

| Variable | Default |
|----------|---------|
|`USAGE_LOGGERS_URL` | `"http://localhost:7701/message"` |
|`USAGE_LOGGERS_RULES` | `"include debug"` |
|`USAGE_LOGGERS_EBPF_ROLE` | `"client"` |
|`USAGE_LOGGERS_EBPF_EXPATH` | `"/lib/x86_64-linux-gnu/libssl.so.3"` |

The values can be modified by updating the `.env` file generated with `make dotenv`.

### Compile and run!

```bash
make build run
```
