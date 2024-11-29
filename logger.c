//go:build ignore

// © 2016-2024 Graylog, Inc.
//
// Based on sslsniff from BCC by Adrian Lopez & Mark Drayton.

#include "vmlinux.h"
// #include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>


// #define DEBUG_ENABLED 0
#define MAX_BYTES 1024


struct data_buf_t {
    u32 id;
    const char* buf;
} buf_stash;

struct data_t {
    // u32 pid;
    // u32 tid;
    // u32 uid;
    // u32 id;
    char data[MAX_BYTES];
} to_transfer;

const struct data_t *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} writes SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, __u32);
//     __type(value, __u32);
//     __uint(max_entries, 10);
// } id_map SEC(".maps");


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

    // u32 xid = 1 << 31;
    // to_transfer.id = (u32) id;
    
    // to_transfer.pid = id >> 32;
    // to_transfer.tid = (u32) id;
    // to_transfer.uid = bpf_get_current_uid_gid();


    bpf_probe_read_user(&to_transfer.data, byte_count, buf_stash.buf);

    if (rw == 0) {
        bpf_ringbuf_output(&reads, &to_transfer, MAX_BYTES, 0);
    } else {
        bpf_ringbuf_output(&writes, &to_transfer, MAX_BYTES, 0);
    }

    // bpf_map_update_elem(&id_map, &k, &xid, 0);
    
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
