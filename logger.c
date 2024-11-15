
//go:build ignore

#include "vmlinux.h"
// #include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>


#define DEBUG_ENABLED 0
#define MAX_BYTES_READ 500

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int flags;
};

struct data_args_t {
    int fd;
    const char* buf;
};

struct data_t {
    int fd;
    char data[MAX_BYTES_READ];
} value;

struct bpf_map_def SEC("maps") stash_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct data_args_t),
	.max_entries = 100,
    .flags       = 0
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct data_t);
	__uint(max_entries, 10);
} active_read_args_map SEC(".maps");

SEC("kprobe/sys_read")
int BPF_KSYSCALL(entry_read, int fd, char* buf, int count) {
    int id = bpf_get_current_pid_tgid();
    struct data_args_t read_args = {};
    
    if (buf == NULL || count <= 0) {
       return 0;
    }

    read_args.fd = fd;
    read_args.buf = buf;

    bpf_map_update_elem(&stash_map, &id, &read_args, BPF_NOEXIST);
    
    //---------------------
    if (DEBUG_ENABLED) {
        int k = 0;
        struct data_t test_data = { fd, count + '0' };
        bpf_map_update_elem(&active_read_args_map, &k, &test_data, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/sys_read")
int BPF_KRETPROBE(ret_read, int bytes_read) {
    int id = bpf_get_current_pid_tgid();
    struct data_args_t* read_args = bpf_map_lookup_elem(&stash_map, &id);

    int k = 1, w = 0;
    if (read_args == NULL) {
        if (DEBUG_ENABLED) {
            struct data_t v = { 999999, "failed: read_args is NULL" };
            bpf_map_update_elem(&active_read_args_map, &k, &v, BPF_ANY);
            // bpf_map_delete_elem(&active_read_args_map, &w);
        }

        bpf_map_delete_elem(&stash_map, &id);
        return 1;
    }

    if (read_args->buf == NULL) {
        if (DEBUG_ENABLED) {
            struct data_t v = { read_args->fd, "failed: buf is NULL" };
            bpf_map_update_elem(&active_read_args_map, &k, &v, BPF_ANY);
            // bpf_map_delete_elem(&active_read_args_map, &w);
        }

        bpf_map_delete_elem(&stash_map, &id);
        return 2;
    }

    if (bytes_read <= 0) {
        if (DEBUG_ENABLED) {
            struct data_t v = { read_args->fd, "failed: bytes_read <= 0" };
            bpf_map_update_elem(&active_read_args_map, &k, &v, BPF_ANY);
            // bpf_map_delete_elem(&active_read_args_map, &w);
        }

        bpf_map_delete_elem(&stash_map, &id);
        return 3;
    }

    if (bytes_read > MAX_BYTES_READ) {
        bytes_read = MAX_BYTES_READ;
    }

    int key = 2;
    value.fd = read_args->fd;
    bpf_probe_read_user(&value.data, bytes_read, read_args->buf);

    bpf_map_update_elem(&active_read_args_map, &key, &value, BPF_ANY);
    // bpf_map_delete_elem(&active_read_args_map, &w);

    bpf_map_delete_elem(&stash_map, &id);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
