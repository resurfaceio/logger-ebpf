//go:build ignore

// © 2016-2024 Graylog, Inc.

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>


#define LOG_DISABLED        0  // Disable all trace logging.
#define LOG_LEVEL_ERROR     1  // Log fatal errors only.
#define LOG_LEVEL_WARN      2  // Log fatal and non-fatal errors.
#define LOG_LEVEL_INFO      3  // Log errors and basic non-error details.
#define LOG_LEVEL_DEBUG     4  // Log errors and non-error details.
#define LOG_LEVEL_TRACE     5  // Log all details.

#define TRACE_CONNECTED     0x0000000F
#define TRACE_CLOSED        0x000000F0
#define TRACE_SSL_CONNECTED 0x00000F00
#define TRACE_SSL_CLOSED    0x0000F000
#define TRACE_SSL_AJAR      0x0000C000
#define TRACE_MASK          0x0000FFFF
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
#define INVALID_FD          MAX_U32_VALUE
#define DEBUG_LEVEL         LOG_LEVEL_TRACE

/**
 * 
 * Data structures
 * 
 */

/**
 * Trace identifier
 * Description: identifies each HTTP request/response, by attempting to
 *              trace the network connection established using the same
 *              file descriptor throughout the socket lifecycle; i.e.
 *              from connect/accept/read/write/close syscalls.
 * 
 * [ fd (32) | flags (32) | ts (64) ]
 */
struct trace_t {
    u32 fd;
    u32 flags;  // 0x0000 00ba where a: connected, b: closed
    u64 ts;
};

/**
 * Temporary buffer
 * Description: used to stash a reference to the buffer used by read/write syscalls.
 * [ id (32) | *buf (8?)]
 */
struct data_buf_t {
    u32 id;
    const char* buf;
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
 * Final packaged data
 */
struct data_t rdata, wdata;

/**
 * Temporary data stash
 */
struct data_buf_t reads_stash, writes_stash;


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
    if (DEBUG_LEVEL >= level)  {
        switch (level)
        {
        case LOG_LEVEL_ERROR:
            bpf_trace_printk(log, sizeof(log), "ERROR", origin, message);
            break;
        case LOG_LEVEL_WARN:
            bpf_trace_printk(log, sizeof(log), "WARN ", origin, message);
            break;
        case LOG_LEVEL_INFO:
            bpf_trace_printk(log, sizeof(log), "INFO ", origin, message);
            break;
        case LOG_LEVEL_DEBUG:
            bpf_trace_printk(log, sizeof(log), "DEBUG", origin, message);
            break;
        case LOG_LEVEL_TRACE:
            bpf_trace_printk(log, sizeof(log), "TRACE", origin, message);
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
    long retval;
    u64 id = bpf_get_current_pid_tgid();
    u64 ktime = bpf_ktime_get_ns();
    struct trace_t* trace = bpf_map_lookup_elem(&traces, &id);
    if (trace != NULL) {
        if (create_only != 0) {
            return 0;
        }
        trace->fd      = (u32) fd;
        trace->flags   = (u32) ZERO;
        trace->ts      = ktime;
        retval = bpf_map_update_elem(&traces, &id, &trace, BPF_EXIST);
    } else {
        struct trace_t new_trace = {
            .fd        = (u32) fd,
            .flags     = (u32) ZERO,
            .ts        = ktime
        };
        retval = bpf_map_update_elem(&traces, &id, &new_trace, BPF_NOEXIST);
    }

    return retval;
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
    u32 current_flags = trace->flags;
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

    if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG) {
        const static char m[] = "[DEBUG] [update_trace_flags    ]: current trace flags [%08x]";
        bpf_trace_printk(m, sizeof(m), trace->flags);
    }

    u32 current_flags = trace->flags;

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

    trace->flags = current_flags & TRACE_MASK;

    if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG) {
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
 * @retval 0 if the reference was stashed successfully.
 * @retval 1 if the underlying network calls are not being traced (trace is NULL).
 * @retval 2 if the underlying network connection does not exist (trace is NOT connected).
 * @retval 3 if the operation specified by rw isn't supported.
 */
static int SSL_entry(void *buf, int rw) {
    u64 id = bpf_get_current_pid_tgid();

    // TODO ? - make map for stashes instead of having only one
    //          data structure to stash reads, and one to stash writes.
    //          Is it necessary? Should there be multiple stashes? For async access? What about race conditions?
    // buf_stash.id = id;

    struct trace_t* trace = bpf_map_lookup_elem(&traces, &id);
    if (trace == NULL) {
        printk(LOG_LEVEL_TRACE, "SSL_entry", "trace is NULL");
        return 1;
    }

    if (!is_connected(trace)) {
        printk(LOG_LEVEL_TRACE, "SSL_entry", "trace is NOT connected");
        return 2;
    }

    if (rw == READ_OP) {
        reads_stash.buf = buf;
    } else if (rw == WRITE_OP) {
        writes_stash.buf = buf;
    } else {
        printk(LOG_LEVEL_ERROR, "SSL_entry", "unsupported operation");
        return 3;
    }

    return 0;
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
    u64 ts;

    int byte_count = PT_REGS_RC(ctx);
    if (byte_count <= 0) {
        printk(LOG_LEVEL_INFO, "SSL_exit", "byte_count <= 0");
        return 3;
    }
    if (byte_count > MAX_BYTES) {
        byte_count = MAX_BYTES;
    }
    u64 packaged_size = sizeof(struct data_t) - MAX_BYTES + byte_count;

    struct trace_t* trace = bpf_map_lookup_elem(&traces, &id);
    if (trace == NULL) {
        printk(LOG_LEVEL_TRACE, "SSL_exit", "trace is NULL");
        return 1;
    } else {
        if (!is_connected(trace)) {
            printk(LOG_LEVEL_TRACE, "SSL_exit", "trace is NOT connected");
            return 2;
        }
        fd = trace->fd;
        ts = trace->ts;
    }

    if (rw == READ_OP) {
        rdata.id = tgid;
        rdata.fd = fd;
        if (bpf_probe_read_user(&rdata.data, byte_count, reads_stash.buf) < 0) {
            return 4;
        }
        return (int) bpf_ringbuf_output(&reads, &rdata, packaged_size, 0);
    } else if (rw == WRITE_OP) {
        wdata.id = tgid;
        wdata.fd = fd;
        if (bpf_probe_read_user(&wdata.data, byte_count, writes_stash.buf) < 0) {
            return 4;
        }
        return (int) bpf_ringbuf_output(&writes, &wdata, packaged_size, 0);
    } else {
        printk(LOG_LEVEL_ERROR, "SSL_exit", "unsupported operation");
        return 5;
    }
}

static int entry_accept(int fd, int is_accept4) {
    if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG) {
        const static char m[] = "[DEBUG] [kprobe/sys_accept%s    ]: attempting connection with socket fd: %d [%x]";
        bpf_trace_printk(m, sizeof(m), is_accept4 == 1 ? "4" : " ", fd, fd);
    }

    init_trace(fd, 0);

    return 0;
}

static int exit_accept(int fd, int is_accept4) {
    if (DEBUG_LEVEL >= LOG_LEVEL_TRACE) {
        const static char m[] = "[TRACE] [kretprobe/sys_accept%s ]: new fd: %d [%x]";
        bpf_trace_printk(m, sizeof(m), is_accept4 == 1 ? "4" : " ", fd, fd);
    }

    if (fd < 0) {
        if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG) {
            const static char m[] = "[DEBUG] [kretprobe/sys_accept%s ]: failed to establish connection. Return code: %d [%x]";
            bpf_trace_printk(m, sizeof(m), is_accept4 == 1 ? "4" : " ", fd, fd);
        }

        delete_trace();

    } else {
        if (DEBUG_LEVEL >= LOG_LEVEL_INFO) {
            const u64 id = bpf_get_current_pid_tgid();
            const static char m[] = "[INFO ] [kretprobe/sys_accept%s ]: connection established for PID %d and FD [%x].";
            bpf_trace_printk(m, sizeof(m), is_accept4 == 1 ? "4" : " ", id, fd);
        }
        
        const long retval = update_trace_flags(TRACE_FLAGS_OP_OR, TRACE_CONNECTED);

        if (DEBUG_LEVEL != LOG_DISABLED && retval !=0) {
            if (retval == 1) {
                printk(LOG_LEVEL_TRACE, "kretprobe/sys_accept", "[update_trace_flags] trace is NULL");
            } else if (retval == 2) {
                printk(LOG_LEVEL_ERROR, "kretprobe/sys_accept", "[update_trace_flags] unsupported operation");
            } else if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG) {
                const static char m[] = "[DEBUG] [kretprobe/sys_accept%s ]: [update_trace_flags] bpf_map_update: %d";
                bpf_trace_printk(m, sizeof(m), is_accept4 == 1 ? "4" : " ", retval);
            }
        }

        // TODO ? - trace fd further? in order to match with bio->num using openssl offsets (1.x)
    }
    return 0;
}

static int entry_rw(int fd, int rw) {
    const long retval = update_trace_fd(fd);
    if (DEBUG_LEVEL != LOG_DISABLED) {
        const char c;
        bpf_get_current_comm((void*) &c, 6);
        if ((bpf_strncmp(&c, 5, "curl") & bpf_strncmp(&c, 6, "nginx")) == 0) {
            const static char m0[] = "[INFO ] [%-22s]: [update_trace_fd] trace was updated sucessfully. New FD: [%x].";
            const static char m1[] = "[TRACE] [%-22s]: [update_trace_fd] no need to update trace - FD is identical [%x].";
            const static char md[] = "[ERROR] [%-22s]: [update_trace_fd] invalid return value: %d.";

            char* origin = rw == READ_OP ? "kprobe/sys_read" : "kprobe/sys_write";

            switch (retval)
            {
            case 0:
                if (DEBUG_LEVEL >= LOG_LEVEL_INFO) bpf_trace_printk(m0, sizeof(m0), origin, fd);
                break;
            case 1:
                if (DEBUG_LEVEL >= LOG_LEVEL_TRACE) bpf_trace_printk(m1, sizeof(m1), origin, fd);
                break;
            case 2:
                printk(LOG_LEVEL_TRACE, origin, "[update_trace_fd] trace is NULL.");
                break;
            case 3:
                printk(LOG_LEVEL_TRACE, origin, "[update_trace_fd] trace is CLOSED.");
                break;
            case 4:
                printk(LOG_LEVEL_TRACE, origin, "[update_trace_fd] trace is NOT connected.");
                break;
            default:
                if (DEBUG_LEVEL >= LOG_LEVEL_ERROR) bpf_trace_printk(md, sizeof(md), origin, retval);
                break;
            }    
        }
    }

    return 0;
}

/**
 * 
 * Kernel probes
 * 
 */

// /**
//  * 
//  * Initialize trace id with fd retrieved from the following syscalls:
//  * - sys_connect (client)
//  * - sys_accept/sys_accept4 (server)
//  */

// /**
//  * sys_connect
//  * Function signature: int connect(int sockfd, void* addr, int addrlen);
//  * Description: The connect() system call connects the socket referred to
//  *              by the file descriptor sockfd to the address specified by addr.
//  */
// SEC("kprobe/sys_connect")
// int BPF_KPROBE(entry_sys_connect, int sockfd, void* serv_addr, int addrlen) {
//     if (DEBUG_LEVEL >= LOG_LEVEL_TRACE) {
//         const static char m[] = "[TRACE] [kprobe/sys_connect    ]: attempting connection with sockfd: %d [%x]";
//         bpf_trace_printk(m, sizeof(m), sockfd, sockfd);
//     }

//     init_trace(sockfd);

//     return 0;
// }

// SEC("kretprobe/sys_connect")
// int BPF_KRETPROBE(ret_sys_connect, int rc) {
//     if (rc < 0) {
//         if (DEBUG_LEVEL >= LOG_LEVEL_TRACE) {
//             const static char m[] = "[TRACE] [kretprobe/sys_connect ]: not connected: %d";
//             bpf_trace_printk(m, sizeof(m), rc);
//         }

//         delete_trace();

//     } else {
//         printk(LOG_LEVEL_TRACE, "kretprobe/sys_connect", "connected!");

//         long retval = update_trace_flags(TRACE_FLAGS_OP_OR, TRACE_CONNECTED);

//         if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG && retval !=0) {
//             if (retval == 1) {
//                 printk(LOG_LEVEL_DEBUG, "kretprobe/sys_connect", "trace is NULL");
//             } else if (retval == 2) {
//                 printk(LOG_LEVEL_DEBUG, "kretprobe/sys_connect", "unsupported operation");
//             } else {
//                 const static char m[] = "[DEBUG] [kretprobe/sys_connect] bpf_map_update: %d";
//                 bpf_trace_printk(m, sizeof(m), retval);
//             }
//         }
//     }

//     return 0;
// }

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
 * Update trace id with fd retrieved from the following syscalls:
 * - sys_read
 * - sys_write
 */

/**
 * sys_read
 * Function signature: int read(int fd, void* buf, int num);
 * Description: Reads num bytes in buf from file descriptor fd.
 */
SEC("kprobe/sys_read")
int BPF_KPROBE(entry_sys_read, int fd, void* buf, int num) {
    return entry_rw(fd, READ_OP);
}

/**
 * sys_read
 * Function signature: int write(int fd, void* buf, int num);
 * Description: Writes num bytes from buf to file descriptor fd.
 */
SEC("kprobe/sys_write")
int BPF_KPROBE(entry_sys_write, int fd, void* buf, int num) {
    return entry_rw(fd, WRITE_OP);
}

/**
 * 
 * Mark message as closed with fd retrieved from the sys_close syscall.
 */

/**
 * sys_close
 * Function signature: int close(int fd);
 * Description: closes a file descriptor, so that it no longer
 *              refers to any file and may be reused. 
 */
SEC("kprobe/sys_close")
int BPF_KPROBE(entry_sys_close, int fd) {
    const long retval = update_trace_fd(fd); // not necessary. This is only here to make the verifier happy enough to print logs.
    if (DEBUG_LEVEL >= LOG_DISABLED) {
        const char c;
        bpf_get_current_comm((void*) &c, 6);
        if (DEBUG_LEVEL >= LOG_LEVEL_TRACE && (bpf_strncmp(&c, 5, "curl") & bpf_strncmp(&c, 6, "nginx")) == 0) {
            const u64 id = bpf_get_current_pid_tgid();
            const static char m[] = "[TRACE] [kprobe/sys_close      ] : id: %d, fd: [%x]";
            bpf_trace_printk(m, sizeof(m), id, fd);
        }
    }

    return 0;
}

SEC("kretprobe/sys_close")
int BPF_KRETPROBE(ret_sys_close, int rc) {
    const long retval = update_trace_flags(TRACE_FLAGS_OP_OR, TRACE_CLOSED);
    if (DEBUG_LEVEL != LOG_DISABLED) {
        const char c;
        bpf_get_current_comm((void*) &c, 6);
        if (DEBUG_LEVEL >= LOG_LEVEL_TRACE && (bpf_strncmp(&c, 5, "curl") & bpf_strncmp(&c, 6, "nginx")) == 0) {
            const static char m[] = "[TRACE] [kretprobe/sys_close   ] : rc: %d";
            bpf_trace_printk(m, sizeof(m), rc);
        }

        if (retval == 1) {
            printk(LOG_LEVEL_DEBUG, "kretprobe/sys_close", "[update_trace_flags] trace is NULL");
        } else if (retval == 2) {
            printk(LOG_LEVEL_ERROR, "kretprobe/sys_close", "[update_trace_flags] unsupported operation");
        } else if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG && retval !=0) {
            const static char m[] = "[DEBUG] [kretprobe/sys_close   ]: [update_trace_flags] bpf_map_update: %d";
            bpf_trace_printk(m, sizeof(m), retval);
        }
    }

    return rc;
}



/**
 * 
 * User probes
 * 
 */

SEC("uprobe/SSL_connect")
int BPF_UPROBE(entry_ssl_connect, void* ssl) {
    if (DEBUG_LEVEL >= LOG_LEVEL_TRACE) {
        const u64 id = bpf_get_current_pid_tgid();
        const static char m[] = "[TRACE] [uprobe/SSL_connect    ]: attempting to establish a connection for PID %d.";
        bpf_trace_printk(m, sizeof(m), id);
    }

    if (init_trace(INVALID_FD, 1) == 0) {
        printk(LOG_LEVEL_DEBUG, "uprobe/SSL_connect", "trace initialized successfully.");
    }

    return 0;
}

SEC("uretprobe/SSL_connect")
int BPF_URETPROBE(ret_ssl_connect) {
    int rc = PT_REGS_RC(ctx);
    if (rc == 1) {
        if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG) {
            const u64 id = bpf_get_current_pid_tgid();
            const static char m[] = "[DEBUG] [uretprobe/SSL_connect ]: connection established for PID %d.";
            bpf_trace_printk(m, sizeof(m), id);
        }

        update_trace_flags(TRACE_FLAGS_OP_OR, TRACE_SSL_CONNECTED);

    } else {
        if (DEBUG_LEVEL >= LOG_LEVEL_TRACE) {
            const u64 id = bpf_get_current_pid_tgid();
            const static char m[] = "[TRACE] [uretprobe/SSL_connect ]: failed to establish connection for PID %d. Return code: %d";
            bpf_trace_printk(m, sizeof(m), id, rc);
        }

        if (delete_trace() == 0) {
            printk(LOG_LEVEL_DEBUG, "uretprobe/SSL_connect", "trace deleted successfully.");
        }
    }

    return 0;
}

SEC("uprobe/SSL_accept")
int BPF_UPROBE(entry_ssl_accept, void* ssl) {
    if (DEBUG_LEVEL >= LOG_LEVEL_TRACE) {
        const u64 id = bpf_get_current_pid_tgid();
        const static char m[] = "[TRACE] [uprobe/SSL_accept     ] : waiting for TLS/SSL handshake for PID %d.";
        bpf_trace_printk(m, sizeof(m), id);
    }

    if (init_trace(INVALID_FD, 1) == 0) {
        printk(LOG_LEVEL_DEBUG, "uprobe/SSL_accept", "trace initialized successfully.");
    }

    return 0;
}

SEC("uretprobe/SSL_accept")
int BPF_URETPROBE(ret_ssl_accept) {
    int rc = PT_REGS_RC(ctx);
    if (rc == 1) {
        if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG) {
            const u64 id = bpf_get_current_pid_tgid();
            const static char m[] = "[DEBUG] [uretprobe/SSL_accept  ]: TLS/SSL handshake successfully completed for PID %d.";
            bpf_trace_printk(m, sizeof(m), id);
        }

        update_trace_flags(TRACE_FLAGS_OP_OR, TRACE_SSL_CONNECTED);

    } else {
        if (DEBUG_LEVEL >= LOG_LEVEL_TRACE) {
            const u64 id = bpf_get_current_pid_tgid();
            const static char m[] = "[TRACE] [uretprobe/SSL_accept  ]: failed to perform a TLS/SSL handshake for PID %d. Return code: %d";
            bpf_trace_printk(m, sizeof(m), id, rc);
        }

        if (delete_trace() == 0) {
            printk(LOG_LEVEL_DEBUG, "uretprobe/SSL_accept", "trace deleted successfully.");
        }
    }

    return 0;
}

SEC("uprobe/SSL_shutdown")
int BPF_UPROBE(entry_ssl_shutdown, void* ssl) {
    if (DEBUG_LEVEL >= LOG_LEVEL_TRACE) {
        const u64 id = bpf_get_current_pid_tgid();
        const static char m[] = "[TRACE] [uprobe/SSL_shutdown   ]: attempting to shutdown an active TLS/SSL connection for PID %d.";
        bpf_trace_printk(m, sizeof(m), id);
    }

    update_trace_flags(TRACE_FLAGS_OP_OR, TRACE_SSL_AJAR);

    return 0;
}

SEC("uretprobe/SSL_shutdown")
int BPF_URETPROBE(ret_ssl_shutdown) {
    int rc = PT_REGS_RC(ctx);
    if (rc == 1) {
        if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG) {
            const u64 id = bpf_get_current_pid_tgid();
            const static char m[] = "[DEBUG] [uretprobe/SSL_shutdown]: TLS/SSL shutdown completed successfully for PID %d.";
            bpf_trace_printk(m, sizeof(m), id);
        }

        update_trace_flags(TRACE_FLAGS_OP_OR, TRACE_SSL_CLOSED);

    } else {
        if (DEBUG_LEVEL >= LOG_LEVEL_TRACE) {
            const u64 id = bpf_get_current_pid_tgid();
            const static char m[] = "[TRACE] [uretprobe/SSL_shutdown]: failed to shutdown TLS/SSL connection for PID %d. Return code: %d";
            bpf_trace_printk(m, sizeof(m), id, rc);
        }
    }

    return 0;
}

SEC("uprobe/SSL_read")
int BPF_UPROBE(entry_ssl_read, void* ssl, void *buf, int num) {
    if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG) {
        const static char m[] = "[DEBUG] [uprobe/SSL_read       ]: will attempt to read from buffer (%d bytes)";
        bpf_trace_printk(m, sizeof(m), num);
    }
    return (SSL_entry(buf, READ_OP));
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(entry_ssl_write, void* ssl, void *buf, int num) {
    if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG) {
        const static char m[] = "[DEBUG] [uprobe/SSL_write      ]: will attempt to write to buffer (%d bytes)";
        bpf_trace_printk(m, sizeof(m), num);
    }
    return (SSL_entry(buf, WRITE_OP));
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ret_ssl_read, int n) {
    if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG) {
        const static char m[] = "[DEBUG] [uretprobe/SSL_read    ]: read %d bytes!";
        if (n > 0) {
            bpf_trace_printk(m, sizeof(m), n);
        } else {
            bpf_trace_printk(m, sizeof(m), 0);
        }
    }

    if (n <= 0 && is_set(TRACE_SSL_AJAR, NULL)) {
        update_trace_flags(TRACE_FLAGS_OP_OR, TRACE_SSL_CLOSED);
        printk(LOG_LEVEL_DEBUG, "uretprobe/SSL_read", "trace is now SSL closed");
    }
    return (SSL_exit(ctx, READ_OP));
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(ret_ssl_write, int n) {
    if (DEBUG_LEVEL >= LOG_LEVEL_DEBUG) {
        const static char m[] = "[DEBUG] [uretprobe/SSL_write   ]: wrote %d bytes!";
        if (n > 0) {
            bpf_trace_printk(m, sizeof(m), n);
        } else {
            bpf_trace_printk(m, sizeof(m), 0);
        }
    }

    if (n <= 0 && is_set(TRACE_SSL_AJAR, NULL)) {
        update_trace_flags(TRACE_FLAGS_OP_OR, TRACE_SSL_CLOSED);
        printk(LOG_LEVEL_DEBUG, "uretprobe/SSL_write", "trace is now SSL closed");
    }
    return (SSL_exit(ctx, WRITE_OP));
}

char __license[] SEC("license") = "Dual MIT/GPL";
