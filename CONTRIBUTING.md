# Contributing
&copy; 2025 Graylog, Inc.

## Configuring Development Environment

Start with latest Ubuntu Noble (24.04.1 or later) on Intel x86 (64-bit) or ARM64 (64-bit)

Install required Go version (1.24.0):
```bash
arch=$(dpkg --print-architecture)
cd /opt
sudo wget https://go.dev/dl/go1.24.0.linux-$arch.tar.gz
sudo tar -xzf go1.24.0.linux-$arch.tar.gz
sudo rm go1.24.0.linux-$arch.tar.gz
export PATH="/opt/go/bin:$PATH"
go version
# 👆 should be 1.24.0
```

Install required packages:
```bash
sudo apt install clang libbpf-dev make git
```

Add required soft link:
```bash
sudo ln -s /usr/bin/llvm-strip-18 /usr/bin/llvm-strip
```

Clone the repo

```bash
cd $HOME
git clone git@github.com:resurfaceio/logger-ebpf.git
```

Make headers

```
cd logger-ebpf
make headers
```

## Running Locally in host

### Set up environment

Make .env file

```
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
