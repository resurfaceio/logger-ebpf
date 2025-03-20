FROM ubuntu:noble
ARG BUILDARCH
RUN apt update && apt upgrade -y && apt install -y wget tar clang make linux-tools-$(uname -r) libbpf-dev && ln -s /usr/bin/llvm-strip-18 /usr/bin/llvm-strip
WORKDIR /opt
RUN wget -q https://go.dev/dl/go1.24.0.linux-${BUILDARCH}.tar.gz && tar -xzf go1.24.0.linux-${BUILDARCH}.tar.gz && rm go1.24.0.linux-${BUILDARCH}.tar.gz
ENV PATH=$PATH:/opt/go/bin
WORKDIR /github/workspace
ENV BUILDSUFFIX=${BUILDARCH}
ENTRYPOINT [ "make" ]
CMD [ "nosudo=1", "suffix=-${BUILDSUFFIX}", "headers", "build" ]
