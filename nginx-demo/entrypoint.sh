#!/bin/sh

ebpf-logger >> /var/log/graylog_ebpf_logger/out.log 2>> /var/log/graylog_ebpf_logger/err.log &
/docker-entrypoint.sh "$@"
