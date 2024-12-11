# Contributing to logger-ebpf

## Configuring Development Environment

Start with latest Ubuntu Noble (24.04.1 or later) on Intel x86 (64-bit).

⚠️ ARM and Apple Silicon are not supported or recommended yet* (see notes)

Install required Go version:
```bash
cd /opt
wget https://go.dev/dl/go1.22.6.linux-amd64.tar.gz
tar -xzf go1.22.6.linux-amd64.tar.gz
export PATH="/opt/go/bin:$PATH"
go version
👆 should be 1.22.6
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
git checkout openssl-ringbuf
make headers
```

#### Environment variables
The variables used by `logger-ebpf` are:

| Variable | Default |
|----------|---------|
|`USAGE_LOGGERS_URL` | `"http://localhost:7701/message"` |
|`USAGE_LOGGERS_RULES` | `"include debug"` |
|`USAGE_LOGGERS_ROLE` | `"client"` |

The values can be modified by updating the `.env` file included in this repo.

### Compile and run!

```bash
make build run
```

------
## ARM Notes

We are still trying to figure out portability. In the meantime, we need to specify a `-target` architecture in `gen.go`, as well as the correct path to any executables in `main.go`. Currently, these are the only two changes required for the logger to work on arm64. However, development is being carried out on amd64 and there are no immediate plans to support arm.

Having said that, if you really wanna try your luck with ARM, do this before:

```
mkdir backups
mv gen.go main.go backups/
sed 's/amd64/arm64/g;s/x86_64/aarch64/g' backups/gen.go > gen.go
sed 's/x86_64/aarch64/g' backups/main.go > main.go
```
