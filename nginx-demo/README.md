# nginx-demo

## Try it yourself!

### Setup

Run **Graylog API Security**

```sh
docker run -v resurface:/db -d --name resurface -p 7700:7700 -p 7701:7701 --restart=always -e DB_HEAP=6g -e POLLING_CYCLE=fast -e TZ=America/Denver resurfaceio/resurface:3.7.84
```

Build the binary (or get a pre-built one from our [releases](https://github.com/resurfaceio/logger-ebpf/releases))

```sh
cd ..
make headers build
```

Build the image

```sh
docker build -t ebpf-logger-nginx:latest --build-arg hostname=mydemo -f nginx-demo/dockerfile .
```

### Run the thing!

Run the `nginx-demo` container

```sh
docker run -d --rm --name nginx-demo --privileged -p 8443:443 ebpf-logger-nginx:latest
```

Make some calls to it

```sh
curl -k -H "Host: mydemo" https://mydemo:8443/json
```

Go to http://localhost:7700/ and see your calls flowing in!


### Cleanup

Stop all containers

```sh
docker stop nginx-demo resurface
```

Remove artifacts (or remove the downloaded binary)

```sh
make clean
```
