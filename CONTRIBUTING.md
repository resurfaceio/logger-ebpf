# Contributing to logger-ebpf

## Configuring Development Environment

Start with latest Ubuntu Jammy (22.0.4.5 or later) on Intel x86 (64-bit).

⚠️ ARM and Apple Silicon are not supported or recommended yet.

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
sudo apt install clang libbpf-dev make
```

Add required soft link:
```bash
sudo ln -s /usr/bin/llvm-strip-14 /usr/bin/llvm-strip
```

Export include variable:
```bash
export C_INCLUDE_PATH=/usr/include/x86_64-linux-gnu/
```

## Running Locally

```bash
cd $HOME
git clone https://github.com/resurfaceio/logger-ebpf.git
cd logger-ebpf
make run
```