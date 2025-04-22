# logger-ebpf
Easily log **encrypted** API calls to your own <a href="https://graylog.org/products/api-security/">security data lake</a>.

This open-source [eBPF](https://ebpf.io/) agent logs API requests and responses to [Graylog API Security](https://graylog.org/products/api-security/)
for analysis and storage. This agent logs encrypted API calls without configuring any encryption keys or making any changes to client or server applications. 

[![CodeFactor](https://www.codefactor.io/repository/github/resurfaceio/logger-ebpf/badge?s=1edfaf41d674519709d3abb9c1836e84b4c3a20f)](https://www.codefactor.io/repository/github/resurfaceio/logger-ebpf)
[![Contributing](https://img.shields.io/badge/contributions-welcome-green.svg)](https://github.com/resurfaceio/logger-ebpf/blob/master/CONTRIBUTING.md)
[![License](https://img.shields.io/github/license/resurfaceio/logger-ebpf?s=1edfaf41d674519709d3abb9c1836e84b4c3a20f)](https://github.com/resurfaceio/logger-ebpf/blob/master/LICENSE)

⚠️ [Graylog API Security](https://graylog.org/products/api-security/) is licensed and installed separately, and runs as a remote service (on Kubernetes) that receives data from this eBPF agent.

## Contents

<ul>
<li><a href="#system-requirements">System Requirements</a></li>
<li><a href="#current-limitations">Current Limitations</a></li>
<li><a href="#environment-variables">Environment Variables</a></li>
<li><a href="#logging-from-linux-vm-or-physical-machine">Logging from Linux VM or Physical Machine</a></li>
<li><a href="#logging-from-docker-container">Logging from Docker Container</a></li>
<li><a href="#logging-from-kubernetes">Logging from Kubernetes</a></li>
<li><a href="#privacy">Protecting User Privacy</a></li>
</ul>

<a name="system-requirements"></a>

## System Requirements

* 64-bit Intel or AMD CPU
* Linux kernel v5.8 or higher
* OpenSSL v1.0 or higher
* Root privileges to run the eBPF agent binary
* Network access to the Kubernetes cluster where [Graylog API Security](https://graylog.org/products/api-security/) is running

<a name="current-limitations"></a>

## Current Limitations

* ARM64 chipsets are not yet supported
* API calls made via HTTP are not logged yet (only HTTPS)
* Only applications using OpenSSL are supported (additional encryption libraries coming soon)
* HTTP v3, UDP, and streaming protocols are not supported

<a name="environment-variables"></a>

## Environment Variables

These environment variables are required to configure this eBPF agent and to control what information is logged.

| Variable Name             | Description                                                                                                                                                                                        |
|---------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| USAGE_LOGGERS_EBPF_EXPATH | Path to OpenSSL shared library<br>Use `ldconfig -p \| grep ssl` to find                                                                                                                            |
| USAGE_LOGGERS_RULES       | [Logging rules](https://go2docs.graylog.org/apisecurity-current/logging_rules/logging_rules.htm) used to mask or remove specific details<br>Use `include debug` to log entire request and response |
| USAGE_LOGGERS_URL         | [Capture URL](https://go2docs.graylog.org/apisecurity-current/capture_api_calls/capture_api_calls.htm) for Graylog API Security instance<br>Looks like `https://GL_APISECURITY_HOST/fluke/message` |

<a name="logging-from-linux-vm-or-physical-machine"></a>

## Logging from Linux VM or Physical Machine

Download agent binary:
```bash
wget https://github.com/resurfaceio/logger-ebpf/releases/download/v1.1.0/ebpf-logger-amd64 && chmod +x ebpf-logger-amd64
```

Run agent binary, with your value for `GL_APISECURITY_HOST`:
```bash
sudo USAGE_LOGGERS_EBPF_EXPATH="/lib/x86_64-linux-gnu/libssl.so.3" USAGE_LOGGERS_RULES="include debug" USAGE_LOGGERS_URL="https://GL_APISECURITY_HOST/fluke/message" ./ebpf-logger-amd64
```

⚠️ Use `CRTL-C` to stop the agent.

<a name="logging-from-docker-container"></a>

## Logging from Docker Container

coming soon!

<a name="logging-from-kubernetes"></a>

## Logging from Kubernetes

coming soon!

<a name="privacy"></a>

## Protecting User Privacy

Loggers always have an active set of [logging rules](https://go2docs.graylog.org/apisecurity-current/logging_rules/logging_rules.htm)
that control what data is logged and how sensitive data is masked. All of the examples above apply a predefined set of rules (`include_debug`),
but logging rules are easily customized to meet your privacy requirements.

---
<small>&copy; 2025 <a href="https://graylog.org/products/api-security/">Graylog, Inc.</a></small>
