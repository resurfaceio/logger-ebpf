# resurfaceio-logger-ebpf
Easily log **encrypted** API requests and responses to your own <a href="https://resurface.io">security data lake</a>.

[![CodeFactor](https://www.codefactor.io/repository/github/resurfaceio/logger-ebpf/badge?s=1edfaf41d674519709d3abb9c1836e84b4c3a20f)](https://www.codefactor.io/repository/github/resurfaceio/logger-ebpf)
[![License](https://img.shields.io/github/license/resurfaceio/logger-ebpf)](https://github.com/resurfaceio/logger-ebpf/blob/master/LICENSE)
[![Contributing](https://img.shields.io/badge/contributions-welcome-green.svg)](https://github.com/resurfaceio/logger-ebpf/blob/master/CONTRIBUTING.md)


## Contents

<ul>
<li><a href="#dependencies">Dependencies</a></li>
<li><a href="#usage">Usage</a></li>
<li><a href="#logging-from-container">Capturing traffic from a containerized application</a></li>
<li><a href="#build-from-source">Building from source</a></li>
<li><a href="#privacy">Protecting User Privacy</a></li>
</ul>


<a name="dependencies"></a>

## Dependencies

Requires Linux kernel v5.8+ and OpenSSL v1.0+

<a name="usage"></a>

## Usage

- Get the apropriate binary for your CPU arch from our [releases](https://github.com/resurfaceio/logger-ebpf/releases).

- Set the [variables](#environment-variables) used by the logger, according to your use case.

- Run binary as a privileged user

```sh
sudo ./ebpf-logger
```

## Environment variables

This plugin has access to five environment variables, but only two of them are required for the logger to work properly.

#### ✔ All API calls are sent to the database running inside the `resurface` container
The environment variable `USAGE_LOGGERS_URL` stores this address, which by default should be the string `"http://localhost:7701/message"`
#### ✔ TLS traffic is captured directly from OpenSSL
Encrypted traffic is captured by adding uprobes to symbols found in the OpenSSL shared library. The environment variable `USAGE_LOGGERS_EBPF_EXPATH` specifies the path to this file. This can be found by running the following command:

```sh
ldconfig -p | grep ssl
```
#### ✔ All API calls are filtered using a set of rules (Optional)
The environment variable `USAGE_LOGGERS_RULES` stores these [logging rules](#protecting-user-privacy) as a string. Even though this variable is optional, it is recommended to set it to `"include debug"` or `"allow_http_url"` when trying the plugin for the first time.
#### ✔ The Logger can capture calls in client mode (Optional)
You can set the environment variable `USAGE_LOGGERS_EBPF_ROLE` to `"client"` for the logger to capture API calls made from a client application (e.g. cURL).
#### ✔ The Logger can be disabled at any time (Optional)
By setting the environment variable `USAGE_LOGGERS_DISABLE` to `true` the logger will be disabled and no API calls will be logged.


<a name="logging-from-container"></a>

## Capturing traffic from a containerized application

### Logging from a running container

-  Copy the binary to the container
```sh
docker cp ebpf-logger mycontainer:/
```

- Exec into the container
```sh
docker exec -it -u root mycontainer sh
```

- Run the application
```sh
./ebpf-logger
```


### Building a new image

You can use your existing container images to build a new one that contains our binary:

```dockerfile
FROM yourapp:itstag

ENV USAGE_LOGGERS_URL="http://172.17.0.1:7701/message"
ENV USAGE_LOGGERS_RULES="include debug"
ENV USAGE_LOGGERS_EBPF_ROLE="server"
ENV USAGE_LOGGERS_EBPF_EXPATH="/lib/x86_64-linux-gnu/libssl.so.3"

COPY --chmod=755 ./ebpf-logger /usr/sbin/ebpf-logger
RUN mkdir /var/log/graylog_ebpf_logger && touch /var/log/graylog_ebpf_logger/out.log /var/log/graylog_ebpf_logger/err.log
ENTRYPOINT [ "/new-entrypoint.sh" ]
```

With `new-entrypoint.sh` following this pattern:

```
#!/bin/sh

ebpf-logger >> /var/log/graylog_ebpf_logger/out.log 2>> /var/log/graylog_ebpf_logger/err.log &
# call your usual entrypoint.sh from here
```

Please, see `nginx-demo/README.md` and try it yourself!

<a name="build-from-source"></a>

## Building from source

Please, see our [CONTRIBUTING.md](https://github.com/resurfaceio/logger-ebpf/blob/master/CONTRIBUTING.md) guide.

<a name="privacy"></a>

## Protecting User Privacy

Loggers always have an active set of <a href="https://resurface.io/rules.html">rules</a> that control what data is logged
and how sensitive data is masked. All of the examples above apply a predefined set of rules, `include_debug`,
but logging rules are easily customized to meet the needs of any application.

<a href="https://go2docs.graylog.org/apisecurity-current/logging_rules/logging_rules.htm">Logging rules documentation</a>

---
<small>&copy; 2016-2025 <a href="https://resurface.io">Graylog, Inc.</a></small>
