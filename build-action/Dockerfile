FROM ubuntu:noble

WORKDIR /opt
RUN wget https://go.dev/dl/go1.22.6.linux-amd64.tar.gz && tar -xzf go1.22.6.linux-amd64.tar.gz && export PATH=$PATH:/usr/local/go/bin >>  /etc/profile
RUN apt update && apt upgrade -y && apt install -y clang make libbpf-dev && ln -s /usr/bin/llvm-strip-18 /usr/bin/llvm-strip
WORKDIR /github/workspace
RUN make headers nosudo=1
ENTRYPOINT [ "make", "build" ]
