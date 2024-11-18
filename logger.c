//go:build ignore

// © 2016-2024 Graylog, Inc.
//
// Based on sslsniff from BCC by Adrian Lopez & Mark Drayton.

#include "vmlinux.h"
// #include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>


// #define DEBUG_ENABLED 0
#define MAX_BYTES 500


struct data_buf_t {
    int id;
    const char* buf;
} buf_stash;

struct SSL_data_t {
    int id;
    char buf[MAX_BYTES];
} data;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct SSL_data_t);
    __uint(max_entries, 10);
} ssl_data_map SEC(".maps");


SEC("uprobe/handshake")
int BPF_UPROBE(entry_ssl, void* ssl, void *buf, int num) {
    int id = bpf_get_current_pid_tgid();

    buf_stash.id = id;
    buf_stash.buf = buf;

    //---------------------
    /*
    if (DEBUG_ENABLED) {
        int k = 0;
        struct data_t test_data = { fd, count + '0' };
        bpf_map_update_elem(&active_read_args_map, &k, &test_data, BPF_ANY);
    }
    */

    return 0;
}


static int SSL_exit(struct pt_regs *ctx, int rw) {
    int id = bpf_get_current_pid_tgid();

    int k = 1;
    if (buf_stash.buf == NULL) {
        /*
        if (DEBUG_ENABLED) {
            struct data_t v = { read_args.fd, "failed: buf is NULL" };
            bpf_map_update_elem(&active_read_args_map, &k, &v, BPF_ANY);
        }
        */
        return 1;
    }

    int byte_count = PT_REGS_RC(ctx);
    if (byte_count <= 0) {
        /*
        if (DEBUG_ENABLED) {
            struct data_t v = { read_args.fd, "failed: bytes_read <= 0" };
            bpf_map_update_elem(&active_read_args_map, &k, &v, BPF_ANY);
        }
        */
        return 2;
    }

    if (byte_count > MAX_BYTES) {
        byte_count = MAX_BYTES;
    }


    int key = 2;
    data.id = buf_stash.id;


    bpf_probe_read_user(&data.buf, byte_count, buf_stash.buf);
    
    bpf_map_update_elem(&ssl_data_map, &key, &data, BPF_ANY);
    
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ret_ssl_read) {
    return (SSL_exit(ctx, 0));
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(ret_ssl_write) {
    return (SSL_exit(ctx, 1));
}

char __license[] SEC("license") = "Dual MIT/GPL";
