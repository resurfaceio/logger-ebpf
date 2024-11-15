//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>



#define DEBUG_ENABLED 0
#define MAX_BYTES_READ 500


struct data_args_t {
    int fd;
    const char* buf;
} read_args;

struct data_t {
    int fd;
    char data[MAX_BYTES_READ];
} value;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct data_t);
	__uint(max_entries, 10);
} active_read_args_map SEC(".maps");


SEC("kprobe/sys_read")
int BPF_KSYSCALL(entry_read, int fd, char* buf, int count) {
    int id = bpf_get_current_pid_tgid();
    
    if (buf == NULL || count <= 0) {
       return 0;
    }

    read_args.fd = fd;
    read_args.buf = buf;
    
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

    int k = 1;
    if (read_args.buf == NULL) {
        if (DEBUG_ENABLED) {
            struct data_t v = { read_args.fd, "failed: buf is NULL" };
            bpf_map_update_elem(&active_read_args_map, &k, &v, BPF_ANY);
        }
        return 1;
    }

    if (bytes_read <= 0) {
        if (DEBUG_ENABLED) {
            struct data_t v = { read_args.fd, "failed: bytes_read <= 0" };
            bpf_map_update_elem(&active_read_args_map, &k, &v, BPF_ANY);
        }
        return 2;
    }

    if (bytes_read > MAX_BYTES_READ) {
        bytes_read = MAX_BYTES_READ;
    }

    int key = 2;
    value.fd = read_args.fd;
    bpf_probe_read_user(&value.data, bytes_read, read_args.buf);

    bpf_map_update_elem(&active_read_args_map, &key, &value, BPF_ANY);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
