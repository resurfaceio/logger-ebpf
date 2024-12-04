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

// Data buffers

struct data_buf_t {
    u32 id;
    const char* buf;
};

struct data_t {
    // u32 pid;
    // u32 tid;
    // u32 uid;
    u32 id;
    char data[MAX_BYTES];
};

// char rdata[MAX_BYTES], wdata[MAX_BYTES];
struct data_t rdata, wdata;

// const struct data_t *unused __attribute__((unused));

struct data_buf_t reads_stash, writes_stash;

// eBPF maps

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


// Main functions

static int SSL_entry(void *buf, int rw) {
    // int id = bpf_get_current_pid_tgid();
    // buf_stash.id = id;

    if (rw == 0) {
        reads_stash.buf = buf;
    } else {
        writes_stash.buf = buf;
    }

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
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = (u32) id;
    u32 tgid = id >> 32;
    // u32 id = (255) + (255 << 8) + (255 << 16) + (255 << 24);  // max u32 = 4294967295

    int byte_count = PT_REGS_RC(ctx);
    if (byte_count <= 0) {
        return 2;
    }

    if (byte_count > MAX_BYTES) {
        byte_count = MAX_BYTES;
    }

    
    if (rw == 0) {
        rdata.id = tgid;
        bpf_probe_read_user(&rdata.data, byte_count, reads_stash.buf);
        bpf_ringbuf_output(&reads, &rdata, byte_count + sizeof(u32), 0);
    } else {
        wdata.id = tgid;
        bpf_probe_read_user(&wdata.data, byte_count, writes_stash.buf);
        bpf_ringbuf_output(&writes, &wdata, byte_count + sizeof(u32), 0);
    }

    
    return 0;
}

// Hooks

SEC("uprobe/SSL_read")
int BPF_UPROBE(entry_ssl_read, void* ssl, void *buf, int num) {
    return (SSL_entry(buf, 0));
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(entry_ssl_write, void* ssl, void *buf, int num) {
    return (SSL_entry(buf, 1));
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
