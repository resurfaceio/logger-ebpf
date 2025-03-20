FROM ubuntu:noble

RUN apt update && apt upgrade -y && apt install -y wget tar clang make linux-tools-$(uname -r) libbpf-dev && ln -s /usr/bin/llvm-strip-18 /usr/bin/llvm-strip
WORKDIR /opt
RUN wget https://go.dev/dl/go1.22.6.linux-amd64.tar.gz && tar -xzf go1.22.6.linux-amd64.tar.gz && rm go1.22.6.linux-amd64.tar.gz
ENV PATH=$PATH:/opt/go/bin
WORKDIR /github/workspace
ENTRYPOINT [ "make" ]
CMD [ "nosudo=1", "headers", "build" ]
