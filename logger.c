
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct data_t {
    char data[100];
} value;

struct entry_t {
    int fd;
    const char* buf;
};

struct ret_t {
    int count;
};

 struct bpf_map_def {
     unsigned int type;
     unsigned int key_size;
     unsigned int value_size;
     unsigned int max_entries;
     unsigned int flags;
 };

struct bpf_map_def SEC("maps") entry_stash_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32), // pid
	.value_size  = sizeof(struct entry_t), // sockfd, *buf
	.max_entries = 100,
    .flags       = 0
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct data_t);
	__uint(max_entries, 100);
} active_read_args_map SEC(".maps");

SEC("kprobe/sys_read")
int syscall__probe_entry_read(struct entry_t* ctx) {
    int id = bpf_get_current_pid_tgid();
    struct entry_t read_args = {};

    read_args.fd = ctx->fd;
    read_args.buf = ctx->buf;
    bpf_map_update_elem(&entry_stash_map, &id, &read_args, BPF_ANY);

    // int k = 0;
    // struct data_t v = { "hi" };
    // bpf_map_update_elem(&active_read_args_map, &k, &v, BPF_ANY);

    return 0;
}

SEC("kretprobe/sys_read")
int syscall__probe_return_read(struct ret_t* ctx) {
    int id = bpf_get_current_pid_tgid();

    int bytes_read = ctx->count;
    struct entry_t* read_args = bpf_map_lookup_elem(&entry_stash_map, &id);

    int key = 1;
    int k = 2;

    if (read_args == NULL) {
        struct data_t v = { "failed: read_args is NULL" };
        bpf_map_update_elem(&active_read_args_map, &k, &v, BPF_ANY);
        return 1;
    }

    if (read_args->buf == NULL) {
        struct data_t v = { "failed: buf is NULL" };
        bpf_map_update_elem(&active_read_args_map, &k, &v, BPF_ANY);
        return 2;
    }

    if (bytes_read <= 0) {
        struct data_t v = { "failed: bytes_read <= 0" };
        bpf_map_update_elem(&active_read_args_map, &k, &v, BPF_ANY);
        return 3;
    }

    if (bytes_read > 100) {
        bytes_read = 100;
    }

    bpf_probe_read_str(&value.data, 100, read_args->buf);

    bpf_map_update_elem(&active_read_args_map, &key, &value, BPF_ANY);
    bpf_map_delete_elem(&entry_stash_map, &id);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
