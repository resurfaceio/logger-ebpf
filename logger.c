//go:build ignore

// © 2025 Graylog, Inc.

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>


#define LOG_DISABLED        0  // Disable all trace logging.
#define LOG_ERROR           1  // Log fatal errors only.
#define LOG_WARN            2  // Log fatal and non-fatal errors.
#define LOG_INFO            3  // Log errors and basic non-error details.
#define LOG_DEBUG           4  // Log errors and non-error details.
#define LOG_TRACE           5  // Log almost all details, except noisy ones (i.e. "trace is NULL" and sys_close logs).
#define LOG_TRACE_ALL       6  // Log all details.

#define TRACE_CONNECTED     0x0000000F
#define TRACE_CLOSED        0x000000F0
#define TRACE_SSL_CONNECTED 0x00000F00
#define TRACE_SSL_CLOSED    0x0000F000
#define TRACE_SSL_AJAR      0x0000C000
#define TRACE_MASK          0xF0000000
#define TRACE_FLAGS_OP_AND  1
#define TRACE_FLAGS_OP_OR   2
#define TRACE_FLAGS_OP_XOR  3
#define TRACE_FLAGS_OP_SHR  4
#define TRACE_FLAGS_OP_SHL  5
#define TRACE_FLAGS_OP_NOT  6

#define READ_OP             0
#define WRITE_OP            1

#define ZERO                0
#define MAX_U32_VALUE       0xFFFFFFFF  // max u32 = (255) + (255 << 8) + (255 << 16) + (255 << 24) = 4294967295

#define MAX_BYTES           1024
#define POISON              0x8D0003048D0304F0
#define INVALID_FD          MAX_U32_VALUE
#define LOG_LEVEL           LOG_DEBUG

/**
 * 
 * Data structures
 * 
 */

/**
 * Trace identifier
 * Description: holds the value of the socket file descriptor used to establish
 *              the underlying network connection for each HTTP request/response,
 *              by attempting to trace it throughout the socket lifecycle; i.e.
 *              from connect/accept/read/write/close syscalls. In addition, this
 *              struct keeps track of its initialization time as a u64 timestamp,
 *              as well as references to two buffers: reads, and writes.
 * 
 * [ fd (32) | flags (32) | ts (64) | readsbp (64) | writesbp (64) ]
 */
struct trace_t {
    u32 fd;
    u32 flags;  // 0x0000 00ba where a: connected, b: closed
    u64 ts;
    uintptr_t readsbp;
    uintptr_t writesbp;
};

/**
 * Data package
 * Descrption: package with data to be sent to application in userspace through eBPF maps.
 * [ id (32) | fd (32) | data (MAX_BYTES)]
 */
struct data_t {
    u32 id;
    u32 fd;
    char data[MAX_BYTES];
};

const struct trace_t *unused __attribute__((unused));  // auto generates a given Go type with bpfgo

/**
 * 
 * Variable declarations
 */

/**
 * Packaged data
 */
struct data_t rdata, wdata;


/**
 * 
 * eBPF Maps
 * 
 */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} writes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct trace_t);
    __uint(max_entries, 100);
} traces SEC(".maps");


/**
 *
 * Helper functions
 *
 */

/**
 * @name printk
 * @brief Prints line to /sys/kernel/tracing/trace, according to a specified log level.
 * @param level Category of the log event.
 * @param origin Label for the event origin.
 * @param message Message to log.
 */
static void printk(int level, char* origin, char* message) {
    const static char log[] = "[%-5s] [%-22s]: %s";
    if (LOG_LEVEL >= level)  {
        switch (level)
        {
        case LOG_ERROR:
            bpf_trace_printk(log, sizeof(log), "ERROR", origin, message);
            break;
        case LOG_WARN:
            bpf_trace_printk(log, sizeof(log), "WARN ", origin, message);
            break;
        case LOG_INFO:
            bpf_trace_printk(log, sizeof(log), "INFO ", origin, message);
            break;
        case LOG_DEBUG:
            bpf_trace_printk(log, sizeof(log), "DEBUG", origin, message);
            break;
        case LOG_TRACE:
            bpf_trace_printk(log, sizeof(log), "TRACE", origin, message);
            break;
        case LOG_TRACE_ALL:
            bpf_trace_printk(log, sizeof(log), "TRALL", origin, message);
            break;
        default:
            bpf_trace_printk(log, sizeof(log), "?????", origin, message);
            break;
        }
    }
}


/**
 * 
 * Main functions
 * 
 */

/**
 * @name init_trace
 * @brief Initializes a trace with the current given pid+tgid, and a given file descriptor.
 * 
 * @param fd Socket file descriptor to trace.
 * @param create_only Set to 1 if an existing trace is NOT to be updated. Set to 0 if an existing trace can be reinitialized.
 * @return Propagates return value from bpf_map_update_elem (0 on success, or a negative value in case of failure).
 */
static long init_trace(int fd, int create_only) {
    u64 exists;
    u64 id = bpf_get_current_pid_tgid();
    u64 ktime = bpf_ktime_get_ns();
    struct trace_t* trace = bpf_map_lookup_elem(&traces, &id);
    if (trace != NULL) {
        if (create_only != 0) {
            return 0;
        };
        trace->flags    = (u32) ZERO;
        trace->readsbp  = (uintptr_t) ZERO;
        trace->writesbp = (uintptr_t) ZERO;

        exists = BPF_EXIST;
    } else {
        struct trace_t new_trace = {
            .flags      = (u32) ZERO,
            .readsbp    = (uintptr_t) ZERO,
            .writesbp   = (uintptr_t) ZERO,
        };
        trace = &new_trace;

        exists = BPF_NOEXIST;
    }

    trace->ts = ktime;
    trace->fd = (u32) fd;

    return bpf_map_update_elem(&traces, &id, trace, exists);
}

/**
 * @name delete_trace
 * @brief Deletes the existing trace for the current pid+tgid
 * 
 * @return Propagates return value from bpf_map_delete_elem (0 on success, or a negative value in case of failure).
 */
static long delete_trace() {
    u64 id = bpf_get_current_pid_tgid();
    return bpf_map_delete_elem(&traces, &id);
}

/**
 * is_set
 * @brief Checks the trace identifier flags for a specific flag being set.
 * @param flag Specific flag to check.
 * @param trace Reference to the trace. Pass NULL to attempt trace retrieval.
 * @retval 0 if the specified trace flag is NOT set.
 * @retval 1 if the specified trace flag is set.
 * @retval 2 if the trace is NULL.
 */
static int is_set(u32 flag, struct trace_t* trace) {
    if (trace == NULL) {
        u64 id = bpf_get_current_pid_tgid();
        trace = bpf_map_lookup_elem(&traces, &id);
        if (trace == NULL) {
            return 2;
        }
    }
    u32 masked = trace->flags & flag;
    return masked == flag;
}

/**
 * is_closed
 * @brief Checks if a given trace has been marked as closed.
 * @param trace Reference to the trace. Pass NULL to attempt trace retrieval with current PID.
 * @retval 0 if the given trace is NOT closed.
 * @retval 1 if the given trace is CLOSED.
 * @retval 2 if the retrieved trace is NULL.
 */
static int is_closed(struct trace_t* trace) {
    return is_set(TRACE_CLOSED, trace);
}

/**
 * is_connected
 * @brief Checks if a given trace has been marked either as connected or SSL connected.
 * @param trace Reference to the trace. Pass NULL to attempt trace retrieval with current PID.
 * @retval 0 if the given trace is NOT closed.
 * @retval 1 if the given trace is CLOSED.
 * @retval 2 if the retrieved trace is NULL.
 */
static int is_connected(struct trace_t* trace) {
    int connected = is_set(TRACE_CONNECTED, trace);
    if (connected == 2) return 2;
    int ssl_connected = is_set(TRACE_SSL_CONNECTED, trace);
    if (ssl_connected == 2) return 2;

    return connected || ssl_connected ;
}

/**
 * @name update_trace_fd
 * @brief Updates the trace identifier with a given socket file descriptor.
 * 
 * @param fd Socket file descriptor to trace.
 * @return Propagates return value from bpf_map_update_elem (0 on success, or a negative value in case of failure).
 * @retval 0 if the traced file descriptor was updated successfully.
 * @retval 1 if the given fd value is equal to the current traced file descriptor value, and thus, not updated.
 * @retval 2 if the trace reference is NULL.
 * @retval 3 if the trace is closed for reads/writes.
 * @retval 4 if the trace is not connected.
 */
static long update_trace_fd(int fd) {
    u64 id = bpf_get_current_pid_tgid();

    struct trace_t* trace = bpf_map_lookup_elem(&traces, &id);
    if (trace == NULL) {
        return 2;
    }

    if (is_closed(trace)) {
        return 3;
    }

    if (!is_connected(trace)) {
        return 4;
    }
    if (trace->fd == (u32) fd) {
        return 1;
    }

    trace->fd = (u32) fd;

    return bpf_map_update_elem(&traces, &id, trace, BPF_EXIST);
}

/**
 * update_trace_flags
 * @brief Updates the trace identifier flags.
 * @param operation Bitwise operation to perform on flags
 * @param operand   Second operand for bitwise operation on flags
 * @return Propagates return value from bpf_map_update_elem (0 on success, or a negative value in case of failure).
 * @retval 0 if the traces flags were updated succesfully.
 * @retval 1 if the trace reference is NULL.
 * @retval 2 if the operation specified is not supported.
 */
static long update_trace_flags(int operation, u32 operand) {
    u64 id = bpf_get_current_pid_tgid();

    struct trace_t* trace = bpf_map_lookup_elem(&traces, &id);
    if (trace == NULL) {
        return 1;
    }

    if (LOG_LEVEL >= LOG_DEBUG) {
        const static char m[] = "[DEBUG] [update_trace_flags    ]: current trace flags [%08x]";
        bpf_trace_printk(m, sizeof(m), trace->flags);
    }

    u32 current_flags = trace->flags;

    if ((current_flags & TRACE_MASK) != ZERO) {
        current_flags = (u32) ZERO;
    }

    switch (operation)
    {
    case TRACE_FLAGS_OP_AND:
        current_flags &= operand;
        break;
    case TRACE_FLAGS_OP_OR:
        current_flags |= operand;
        break;
    case TRACE_FLAGS_OP_XOR:
        current_flags ^= operand;
        break;
    case TRACE_FLAGS_OP_SHL:
        current_flags <<= operand;
        break;
    case TRACE_FLAGS_OP_SHR:
        current_flags >>= operand;
        break;
    case TRACE_FLAGS_OP_NOT:
        current_flags = ~operand;
        break;
    default:
        return 2;
    }

    trace->flags = current_flags;

    if (LOG_LEVEL >= LOG_DEBUG) {
        const static char m[] = "[DEBUG] [update_trace_flags    ]: new trace flags     [%08x]";
        bpf_trace_printk(m, sizeof(m), trace->flags);
    }


    return bpf_map_update_elem(&traces, &id, trace, BPF_EXIST);
}

/**
 * @name SSL_entry 
 * @brief Stashes a reference to a given read/write data buffer buf.
 * 
 * To be used at SSL_read/SSL_write function entrypoints.
 * 
 * @param buf Pointer to read/write data buffer
 * @param rw  Flag to indicate type of operation
 * 
 * @return Propagates return value from bpf_map_update_elem (0 on success, or a negative value in case of failure).
 * @retval 0 if the reference was stashed successfully.
 * @retval 1 if the underlying network calls are not being traced (trace is NULL).
 * @retval 2 if the underlying network connection does not exist (trace is NOT connected).
 * @retval 3 if the operation specified by rw isn't supported.
 */
static int SSL_entry(void *buf, int rw) {
    u64 id = bpf_get_current_pid_tgid();

    struct trace_t* trace = bpf_map_lookup_elem(&traces, &id);
    if (trace == NULL) {
        printk(LOG_TRACE, "SSL_entry", "trace is NULL");
        return 1;
    }

    if (!is_connected(trace)) {
        printk(LOG_TRACE, "SSL_entry", "trace is NOT connected");
        return 2;
    }

    if (rw == READ_OP) {
        trace->readsbp = (uintptr_t) buf;
    } else if (rw == WRITE_OP) {
        trace->writesbp = (uintptr_t) buf;
    } else {
        printk(LOG_ERROR, "SSL_entry", "unsupported operation");
        return 3;
    }

    return bpf_map_update_elem(&traces, &id, trace, BPF_EXIST);
}

/**
 * @name SSL_exit
 * @brief Retrieves read/written data from stashed buffer,
 * adds its corresponding trace identifier, and
 * updates the output ringbuf accordingly.
 * 
 * To be used at SSL_read/SSL_write function return points.
 * 
 * @param ctx Pointer to eBPF context variable
 * @param rw  Flag to indicate type of operation
 * 
 * @return Propagates return value (casted to int) from bpf_ringbuf_output (0 on success, or a negative value in case of failure).
 * 
 * @retval 0 if data was successfully retrieved from buffer and submitted to output ringbuf.
 * @retval 1 if the underlying network calls are not being traced (trace is NULL).
 * @retval 2 if the underlying network connection does not exist (trace is NOT connected).
 * @retval 3 if the number of bytes read/written specified by the function rc is invalid.
 * @retval 4 if data couldn't be read from the stashed buffer.
 * @retval 5 if the operation specified by rw isn't supported.
 */
static int SSL_exit(struct pt_regs *ctx, int rw) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = (u32) id;
    u32 tgid = id >> 32;
    u32 fd;
    char *buf;

    int byte_count = PT_REGS_RC(ctx);
    if (byte_count <= 0) {
        printk(LOG_DEBUG, "SSL_exit", "byte_count <= 0");
        return 3;
    }
    if (byte_count > MAX_BYTES) {
        byte_count = MAX_BYTES;
    }
    u64 packaged_size = sizeof(struct data_t) - MAX_BYTES + byte_count;

    struct trace_t* trace = bpf_map_lookup_elem(&traces, &id);
    if (trace == NULL) {
        printk(LOG_TRACE, "SSL_exit", "trace is NULL");
        return 1;
    }

    if (!is_connected(trace)) {
        printk(LOG_TRACE, "SSL_exit", "trace is NOT connected");
        return 2;
    }

    fd = trace->fd;

    printk(LOG_DEBUG, "SSL_exit", "message ready for ringbuf");

    if (rw == READ_OP) {
        rdata.id = tgid;
        rdata.fd = fd;
        buf = (char *) trace->readsbp;
        if (bpf_probe_read_user(&rdata.data, byte_count, buf) < 0) {
            return 4;
        }
        return (int) bpf_ringbuf_output(&reads, &rdata, packaged_size, 0);
    } else if (rw == WRITE_OP) {
        wdata.id = tgid;
        wdata.fd = fd;
        buf = (char *) trace->writesbp;
        if (bpf_probe_read_user(&wdata.data, byte_count, buf) < 0) {
            return 4;
        }
        return (int) bpf_ringbuf_output(&writes, &wdata, packaged_size, 0);
    } else {
        printk(LOG_ERROR, "SSL_exit", "unsupported operation");
        return 5;
    }
}

static int entry_accept(int fd, int is_accept4) {
    if (LOG_LEVEL >= LOG_DEBUG) {
        const static char m[] = "[DEBUG] [kprobe/sys_accept%s    ]: attempting connection with socket fd: %d [%x]";
        bpf_trace_printk(m, sizeof(m), is_accept4 == 1 ? "4" : " ", fd, fd);
    }

    long rc = init_trace(fd, 0);
    
    if (LOG_LEVEL >= LOG_DEBUG) {
        const static char m[] = "[DEBUG] [kprobe/sys_accept%s    ]: init_trace rc: %d";
        bpf_trace_printk(m, sizeof(m), is_accept4 == 1 ? "4" : " ", rc);
    }

    return 0;
}

static int exit_accept(int fd, int is_accept4) {
    if (LOG_LEVEL >= LOG_TRACE) {
        const static char m[] = "[TRACE] [kretprobe/sys_accept%s ]: new fd: %d [%x]";
        bpf_trace_printk(m, sizeof(m), is_accept4 == 1 ? "4" : " ", fd, fd);
    }

    if (fd < 0) {
        if (LOG_LEVEL >= LOG_DEBUG) {
            const static char m[] = "[DEBUG] [kretprobe/sys_accept%s ]: failed to establish connection. Return code: %d [%x]";
            bpf_trace_printk(m, sizeof(m), is_accept4 == 1 ? "4" : " ", fd, fd);
        }

        delete_trace();

    } else {
        if (LOG_LEVEL >= LOG_INFO) {
            const u64 id = bpf_get_current_pid_tgid();
            const static char m[] = "[INFO ] [kretprobe/sys_accept%s ]: connection established for PID %d and FD [%x].";
            bpf_trace_printk(m, sizeof(m), is_accept4 == 1 ? "4" : " ", id, fd);
        }
        
        const long retval = update_trace_flags(TRACE_FLAGS_OP_OR, TRACE_CONNECTED);

        if (LOG_LEVEL != LOG_DISABLED && retval !=0) {
            if (retval == 1) {
                printk(LOG_TRACE, "kretprobe/sys_accept", "[update_trace_flags] trace is NULL");
            } else if (retval == 2) {
                printk(LOG_ERROR, "kretprobe/sys_accept", "[update_trace_flags] unsupported operation");
            } else if (LOG_LEVEL >= LOG_DEBUG) {
                const static char m[] = "[DEBUG] [kretprobe/sys_accept%s ]: [update_trace_flags] bpf_map_update: %d";
                bpf_trace_printk(m, sizeof(m), is_accept4 == 1 ? "4" : " ", retval);
            }
        }
    }
    return 0;
}

static int poison_well() {
    const static u64 pill = POISON;

    u64 id = bpf_get_current_pid_tgid();

    struct trace_t* trace = bpf_map_lookup_elem(&traces, &id);
    if (trace == NULL) {
        printk(LOG_TRACE, "poison_well", "trace is NULL");
        return 1;
    }
    u64 fd = (u64) trace->fd;
    
    u128 packaged = pill;
    packaged = (packaged << 64) | (fd << 32) | (id >> 32);
    
    printk(LOG_DEBUG, "poison_well", "pill ready for ringbuf");

    int r = (int) bpf_ringbuf_output(&reads, &packaged, sizeof(u128), 0);
    int w = (int) bpf_ringbuf_output(&writes, &packaged, sizeof(u128), 0);

    return r || w;
}

/**
 * 
 * Kernel probes
 * 
 */

/**
 * 
 * Initialize trace id with fd retrieved from sys_accept/sys_accept4 calls (server mode)
 */

/**
 * sys_accept
 * Function signature: int accept(int sockfd, void* addr, int addrlen);
 * Description: The accept() system call extracts the first connection request
 *              on the queue of pending connections for the listening
 *              socket sockfd, creates a new connected socket, and returns
 *              a new file descriptor referring to that socket.
 */

SEC("kprobe/sys_accept")
int BPF_KPROBE(entry_sys_accept, int sockfd, void* addr, void* addrlen) {
    return entry_accept(sockfd, 0);
}

SEC("kretprobe/sys_accept")
int BPF_KRETPROBE(ret_sys_accept, int fd) {
    return exit_accept(fd, 0);
}

/**
 * sys_accept4
 * Function signature: int accept4(int sockfd, void* addr, int addrlen);
 * Description: The accept4() system call extracts the first connection request
 *              on the queue of pending connections for the listening
 *              socket sockfd, creates a new connected socket, and returns
 *              a new file descriptor referring to that socket.
 * 
 *              The accept4 is a non-standard linux extension for the accept syscall.
 */

SEC("kprobe/sys_accept4")
int BPF_KPROBE(entry_sys_accept4, int sockfd, void* addr, void* addrlen, int flags) {
    return entry_accept(sockfd, 1);
}

SEC("kretprobe/sys_accept4")
int BPF_KRETPROBE(ret_sys_accept4, int fd) {
    return exit_accept(fd, 1);
}


/**
 * 
 * User probes
 * 
 */

SEC("uprobe/SSL_connect")
int BPF_UPROBE(entry_ssl_connect, void* ssl) {
    if (LOG_LEVEL >= LOG_TRACE) {
        const u64 id = bpf_get_current_pid_tgid();
        const static char m[] = "[TRACE] [uprobe/SSL_connect    ]: attempting to establish a connection for PID %d.";
        bpf_trace_printk(m, sizeof(m), id);
    }

    if (init_trace(INVALID_FD, 1) == 0) {
        printk(LOG_DEBUG, "uprobe/SSL_connect", "trace initialized successfully.");
    }

    return 0;
}

SEC("uretprobe/SSL_connect")
int BPF_URETPROBE(ret_ssl_connect) {
    int rc = PT_REGS_RC(ctx);
    if (rc == 1) {
        if (LOG_LEVEL >= LOG_DEBUG) {
            const u64 id = bpf_get_current_pid_tgid();
            const static char m[] = "[DEBUG] [uretprobe/SSL_connect ]: connection established for PID %d.";
            bpf_trace_printk(m, sizeof(m), id);
        }

        update_trace_flags(TRACE_FLAGS_OP_OR, TRACE_SSL_CONNECTED);

    } else {
        if (LOG_LEVEL >= LOG_TRACE) {
            const u64 id = bpf_get_current_pid_tgid();
            const static char m[] = "[TRACE] [uretprobe/SSL_connect ]: failed to establish connection for PID %d. Return code: %d";
            bpf_trace_printk(m, sizeof(m), id, rc);
        }

        if (delete_trace() == 0) {
            printk(LOG_DEBUG, "uretprobe/SSL_connect", "trace deleted successfully.");
        }
    }

    return 0;
}

SEC("uprobe/SSL_accept")
int BPF_UPROBE(entry_ssl_accept, void* ssl) {
    if (LOG_LEVEL >= LOG_TRACE) {
        const u64 id = bpf_get_current_pid_tgid();
        const static char m[] = "[TRACE] [uprobe/SSL_accept     ] : waiting for TLS/SSL handshake for PID %d.";
        bpf_trace_printk(m, sizeof(m), id);
    }

    if (init_trace(INVALID_FD, 1) == 0) {
        printk(LOG_DEBUG, "uprobe/SSL_accept", "trace initialized successfully.");
    }

    return 0;
}

SEC("uretprobe/SSL_accept")
int BPF_URETPROBE(ret_ssl_accept) {
    int rc = PT_REGS_RC(ctx);
    if (rc == 1) {
        if (LOG_LEVEL >= LOG_DEBUG) {
            const u64 id = bpf_get_current_pid_tgid();
            const static char m[] = "[DEBUG] [uretprobe/SSL_accept  ]: TLS/SSL handshake successfully completed for PID %d.";
            bpf_trace_printk(m, sizeof(m), id);
        }

        update_trace_flags(TRACE_FLAGS_OP_OR, TRACE_SSL_CONNECTED);

    } else {
        if (LOG_LEVEL >= LOG_TRACE) {
            const u64 id = bpf_get_current_pid_tgid();
            const static char m[] = "[TRACE] [uretprobe/SSL_accept  ]: failed to perform a TLS/SSL handshake for PID %d. Return code: %d";
            bpf_trace_printk(m, sizeof(m), id, rc);
        }

        if (delete_trace() == 0) {
            printk(LOG_DEBUG, "uretprobe/SSL_accept", "trace deleted successfully.");
        }
    }

    return 0;
}

SEC("uprobe/SSL_shutdown")
int BPF_UPROBE(entry_ssl_shutdown, void* ssl) {
    if (LOG_LEVEL >= LOG_TRACE) {
        const u64 id = bpf_get_current_pid_tgid();
        const static char m[] = "[TRACE] [uprobe/SSL_shutdown   ]: attempting to shutdown an active TLS/SSL connection for PID %d.";
        bpf_trace_printk(m, sizeof(m), id);
    }

    if (poison_well() == 0) {
        printk(LOG_DEBUG, "uprobe/SSL_shutdown", " poison pill sent.");
    }
    if (delete_trace() == 0) {
        printk(LOG_DEBUG, "uprobe/SSL_shutdown", "trace deleted successfully.");
    }

    return 0;
}

SEC("uprobe/SSL_read")
int BPF_UPROBE(entry_ssl_read, void* ssl, void *buf, int num) {
    if (LOG_LEVEL >= LOG_DEBUG) {
        const static char m[] = "[DEBUG] [uprobe/SSL_read       ]: will attempt to read from buffer (%d bytes)";
        bpf_trace_printk(m, sizeof(m), num);
    }
    return (SSL_entry(buf, READ_OP));
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(entry_ssl_write, void* ssl, void *buf, int num) {
    if (LOG_LEVEL >= LOG_DEBUG) {
        const static char m[] = "[DEBUG] [uprobe/SSL_write      ]: will attempt to write to buffer (%d bytes)";
        bpf_trace_printk(m, sizeof(m), num);
    }
    return (SSL_entry(buf, WRITE_OP));
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ret_ssl_read, int n) {
    if (LOG_LEVEL >= LOG_DEBUG) {
        const static char m[] = "[DEBUG] [uretprobe/SSL_read    ]: read %d bytes!";
        if (n > 0) {
            bpf_trace_printk(m, sizeof(m), n);
        } else {
            bpf_trace_printk(m, sizeof(m), 0);
        }
    }

    return (SSL_exit(ctx, READ_OP));
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(ret_ssl_write, int n) {
    if (LOG_LEVEL >= LOG_DEBUG) {
        const static char m[] = "[DEBUG] [uretprobe/SSL_write   ]: wrote %d bytes!";
        if (n > 0) {
            bpf_trace_printk(m, sizeof(m), n);
        } else {
            bpf_trace_printk(m, sizeof(m), 0);
        }
    }

    return (SSL_exit(ctx, WRITE_OP));
}

char __license[] SEC("license") = "Dual MIT/GPL";
