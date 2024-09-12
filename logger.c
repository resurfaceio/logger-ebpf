
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

struct data_args_t {
    int fd;
    const char* buf;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 100);
} active_read_args_map SEC(".maps");

SEC("ksyscall/read")
int BPF_KSYSCALL(char* entry_read, int fd, char* buf, int count) {
    int id = bpf_get_current_pid_tgid();
    struct data_args_t read_args = {};

    read_args.fd = fd;
    read_args.buf = buf;
    bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_NOEXIST);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
