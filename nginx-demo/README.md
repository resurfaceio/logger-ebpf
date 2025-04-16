# nginx-demo

## Try it yourself!

### Setup

Run **Graylog API Security**

```sh
docker run -v resurface:/db -d --name resurface -p 7700:7700 -p 7701:7701 -e DB_HEAP=6g -e POLLING_CYCLE=fast -e TZ=America/Denver resurfaceio/resurface:3.7.84
```

**Either** build the binary **or** get a pre-built one from our [releases](https://github.com/resurfaceio/logger-ebpf/releases)

<table>
<tr>
<td> Build your own binary </td> <td> <a href="https://github.com/resurfaceio/logger-ebpf/releases/tag/v1.1.0">Download</a> pre-built binary </td>
</tr>
<tr>
<td>

```sh
cd ..
make headers build
```

</td>
<td>
    
```sh
cd ..
mv ~/Downloads/ebpf-logger-amd64 ebpf-logger
```
</td>
</tr>
</table>

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
