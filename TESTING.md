# Testing logger-ebpf

Quality is very important to us, but we can only test so many applications and Linux versions on our own.

The following sections cover how to validate that this logger is working properly in your target environment.

If anything doesn't work right or could be made better, we're grateful for your feedback!  

## 1. Does the logger run and initialize properly?

There are many different Linux distributions and kernel versions, so the first test is that the logger starts properly in your target environment.

These output messages indicate that the logger is running successfully:
```text
2025/04/23 16:34:38 main.go:104: executable:  /lib/x86_64-linux-gnu/libssl.so.3
2025/04/23 16:34:38 loader.go:28:  programs loaded successfully!
2025/04/23 16:34:38 main.go:165: logger is initialized
2025/04/23 16:34:38 main.go:167:   url:    https://<your Graylog API Security instance>/fluke/message
2025/04/23 16:34:38 main.go:168:   rules:  include debug
2025/04/23 16:34:38 main.go:170: Waiting for any OpenSSL calls...
```

These output messages indicate that the logger was not run with required root permissions:
```text
2025/04/23 16:42:31 main.go:104: executable:  /lib/x86_64-linux-gnu/libssl.so.3
2025/04/23 16:42:31 loader.go:38: Removing memlock:failed to set memlock rlimit: operation not permitted
```

If the logger fails to start, check that the kernel version is 5.8 or later:
```bash
uname -r
```

The logger may fail to start due to permission issues in Docker or Kubernetes environments, which is largely why these are not officially supported yet.

If the kernel version is supported and you aren't running containers, please open a 
[new issue](https://github.com/resurfaceio/logger-ebpf/issues) including your kernel version, OS version (`cat /etc/issue`), and CPU version.

## 2. Is traffic captured from the target application stack?

Now that the logger is running, the next step is to verify that API calls are being captured.

You'll need a Graylog API Security installation that is reachable on the network from hosts where the logger is running.
If you don't have Graylog API Security installed yet,
please [sign up for a free license](https://go2.graylog.org/api-security-free) and then
[follow the online documentation](https://go2docs.graylog.org/apisecurity-current/what_is_api_security/what_is_graylog_api_security.htm)
to install this on your network.

⚠️ The only API calls captured by default are HTTPS calls where the target Linux host acts as the server. Self-signed certificates are ok.

⚠️ Calls made using client-mode applications on the target Linux host (like `curl` or `wget`) will not be logged, unless the logger is 
configured to run in client mode (which is typically used for development, and not for server applications).

⚠️ Calls to server-mode applications written in Go or using custom encryption libraries will not be logged. This logger currently supports OpenSSL applications only.

If you're making HTTPS calls to your server application, but calls aren't visible in the Graylog API Security console, first check that the network hostname is correct in the output log, and that this name resolves from the Linux host:
```bash
2025/04/23 16:34:38 main.go:165: logger is initialized
2025/04/23 16:34:38 main.go:167:   url:    https://<...>/fluke/message
```

If you're certain that the networking is right, but nothing is being logged, please open a [new issue](https://github.com/resurfaceio/logger-ebpf/issues)
for help troubleshooting at a deeper level.

## 3. Do captured requests match captured responses?

The logger sees the request and response at different times and must merge them before the API call is sent to Graylog API Security.

If this merging mechanism fails, Graylog API Security may display requests without a response, responses without a request, or requests and responses
from different calls mixed together. If you see garbled data when using Graylog API Security, please open
a [new issue](https://github.com/resurfaceio/logger-ebpf/issues) so we can recommend next steps for your target environment.

## 4. Are original requests or responses impacted by logging?

It is important that the logger not interfere with any applications and that the overhead of logging is kept to a minimum.
This must include normal operations as well as any misconfiguration or error states that the logger encounters.

* The logger should be able to start and stop without impacting any running applications.
* The logger should not interfere with API calls when misconfigured (like an invalid host name for the capture URL).
* The logger should not alter or truncate the original request or response.
* The logger should not cause timeouts or significantly reduce the server processing time.

⚠️ This logger is in beta and not currently recommended for high-volume, high-concurrency environments.

We are currently formalizing plans for regular stress/scale testing for this project. If you see performance or quality issues
in your environment, please open a [new issue](https://github.com/resurfaceio/logger-ebpf/issues) to request adding your configuration
to regular testing.

---
<small>&copy; 2025 <a href="https://graylog.org/products/api-security/">Graylog, Inc.</a></small>
