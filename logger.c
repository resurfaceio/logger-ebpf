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
#define MAX_U32_VALUE       0xFFFFFFFF

#define MAX_BYTES           16384    // max 16 kiB per iteration
#define MAX_ITERATIONS      512      // max  8 MiB per HTTPS payload
#define RINGBUF_SIZE        16777216 // max 16 MiB per ringbuf (32 MiB in total for both req and resp)

#define POISON              0x8D0003048D0304F0
#define COUNTER_LOCK        MAX_U32_VALUE
#define LOG_LEVEL           LOG_TRACE

/**
 * 
 * Data structures
 * 
 */

/**
 * Trace identifier
 * Description: holds the value of the *SSL used to establish the TLS connection for 
 *              the TCP connection carrying each HTTP request/response, by attempting
 *              to trace it throughout its lifecycle; i.e. from SSL_new, SSL_connect/accept, 
 *              SSL_read/write, SSL_shutdown, and SSL_free calls. In addition, this struct 
 *              keeps track of its initialization time as a u64 timestamp, as well as 
 *              references to two buffers: reads, and writes.
 * 
 * [  ssl_conn (64) | ssl_count (32) | flags (32) | created_at (64) | rbuf (64) | wbuf (64) ]
 */
struct trace_t {
    u64 ssl_conn;
    u32 ssl_count;
    u32 flags;  // 0x0000 00ba where a: connected, b: closed
    u64 created_at;
    uintptr_t rbuf;
    uintptr_t wbuf;
};

/**
 * Data package
 * Descrption: package with char data to be sent to application in userspace through eBPF maps.
 * [ ts (64) | pid_tgid (64) | ssl_ptr (64) | ssl_count (32) | data length (32) | data (MAX_BYTES)]
 */
struct data_t {
    u64 ts;
    u64 pid;
    u64 sslp;
    u32 sslc;
    u32 len;
    char data[MAX_BYTES];
};

/**
 * Pill package
 * Descrption: package with a single u64 member to be sent to application in userspace through eBPF maps.
 * [ ts (64) | pid_tgid (64) | ssl_ptr (64) | ssl_count (32) | pill length (32) | pill (64)]
 */
struct pill_t {
    u64 ts;
    u64 pid;
    u64 sslp;
    u32 sslc;
    u32 len;
    u64 pill;
};


/**
 * 
 * eBPF Maps
 * 
 */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} writes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct trace_t);
    __uint(max_entries, 100);
} traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 1000);
} counts SEC(".maps");

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
 * @name min
 * @brief Compares two integers and returns the smallest.
 * @param a integer to compare.
 * @param b another integer to compare.
 * @return smallest of the two arguments.
 */
static int min(int a, int b) {
    if (a < b) {
        return a;
    }
    return b;
}

/**
 * @name enforce_bounds
 * @brief Constrains an long integer within a given range.
 * @param n long integer to constrain.
 * @param lower smallest possible value in the allowed range.
 * @param upper largest possible value in the allowed range.
 * @return n if lower < n < upper. Otherwise, the nearest bound is enforced.
 */
static long enforce_bounds(long n, long lower, long upper) {
    if (n < lower) n = lower;
    if (n > upper) n = upper;
    return n;
}

/**
 * @name enforce_bounds_int
 * @brief Constrains an integer within a given range.
 * @param i integer to constrain.
 * @param lower smallest possible value in the allowed range.
 * @param upper largest possible value in the allowed range.
 * @return i if lower < n < upper. Otherwise, the nearest bound is enforced.
 */
static int enforce_bounds_int(int i, int lower, int upper) {
    return (int) enforce_bounds((long) i, (long) lower, (long) upper);
}

/**
 * @name cat2long
 * @brief Concatenate two integers into a long integer.
 * @param lower integer to concatenate in the lower half of the return value.
 * @param upper integer to concatenate in the upper half of the return value.
 * @return long integer of the form: [upper|lower]
 */
static long cat2long(int lower, int upper) {
    long c = upper;
    c <<= (sizeof(int) * 8);
    return c | lower;
}

/**
 * 
 * Main functions
 * 
 */

 /**
 * @name up_count
 * @brief Increases the count for a given SSL connection, if counter is unlocked. Does nothing if counter is locked.
 * 
 * @param ssl *SSL Connection to trace.
 * @return Current count if positive, or propagated return value from bpf_map_delete_elem (0 on success, or a negative value in case of failure).
 */
static int up_count(u64 ssl) {
    u64* count = bpf_map_lookup_elem(&counts, &ssl);
    if (count == NULL) {
        u64 new_count = cat2long((u32) ZERO, COUNTER_LOCK);
        return (int) bpf_map_update_elem(&counts, &ssl, &new_count, BPF_NOEXIST);
    }

    u32 c = (u32) *count;
    u32 lock = *count >> 32;
    if (lock != COUNTER_LOCK) {
        u64 new_count = cat2long(++c, COUNTER_LOCK);
        int errno = (int) bpf_map_update_elem(&counts, &ssl, &new_count, BPF_EXIST);
        if (errno < 0) return errno;
    }
    
    return c;
}

 /**
 * @name unlock_counter
 * @brief Unlocks the counter for a given *SSL.
 * 
 * @param ssl *SSL Connection with counter to be unlocked.
 * @return Propagates return value from bpf_map_delete_elem (0 on success, or a negative value in case of failure).
 * @retval 1 if count does not exist in map.
 */
static int unlock_counter(u64 ssl) {
    u64* count = bpf_map_lookup_elem(&counts, &ssl);
    if (count == NULL) {
        return 1;
    }

    u32 c = (u32) *count;
    u32 lock = *count >> 32;
    if (lock == COUNTER_LOCK) {
        u64 new_count = cat2long(c, (int) ZERO);
        return (int) bpf_map_update_elem(&counts, &ssl, &new_count, BPF_EXIST);
    }

    return 0;
}

/**
 * @name init_trace
 * @brief Initializes a trace with the current given pid+tgid, and a given SSL memory address value.
 * 
 * @param ssl *SSL Connection to trace.
 * @return Propagates return value from bpf_map_update_elem (0 on success, or a negative value in case of failure).
 */
static long init_trace(u64 ssl) {
    u64 exists;
    u64 id = bpf_get_current_pid_tgid();
    u64 ktime = bpf_ktime_get_ns();
    struct trace_t* trace = bpf_map_lookup_elem(&traces, &id);
    if (trace != NULL) {
        trace->flags     = (u32) ZERO;
        trace->rbuf      = (uintptr_t) ZERO;
        trace->wbuf      = (uintptr_t) ZERO;

        exists = BPF_EXIST;
    } else {
        struct trace_t new_trace = {
            .flags     = (u32) ZERO,
            .rbuf      = (uintptr_t) ZERO,
            .wbuf      = (uintptr_t) ZERO,
        };
        trace = &new_trace;

        exists = BPF_NOEXIST;
    }

    trace->created_at = ktime;
    trace->ssl_conn = ssl;
    trace->ssl_count = up_count(ssl);

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
static int SSL_entry(void* ssl, void *buf, int rw) {
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

    if (trace->ssl_conn != (u64) ssl) {
        printk(LOG_TRACE, "SSL_entry", "wrong SSL pointer!");
        return 1;
    }

    if (rw == READ_OP) {
        trace->rbuf = (uintptr_t) buf;
    } else if (rw == WRITE_OP) {
        trace->wbuf = (uintptr_t) buf;
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
 * @return 0 on success, or a positive value in case of failure.
 * 
 * @retval 0 if data was successfully retrieved from buffer and submitted to output ringbuf.
 * @retval 1 if the underlying network calls are not being traced (trace is NULL).
 * @retval 2 if the underlying network connection does not exist (trace is NOT connected).
 * @retval 3 if the number of bytes read/written specified by the function rc is invalid.
 * @retval 4 if data couldn't be read from the stashed buffer.
 * @retval 5 if data couldn't be submitted to the output ringbuf.
 * @retval 6 if the operation specified by rw isn't supported.
 */
static long SSL_exit(struct pt_regs *ctx, int rw) {
    u64 ktime = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    char *buf;
    long errno;

    int byte_count = PT_REGS_RC(ctx);
    if (byte_count <= 0) {
        printk(LOG_DEBUG, "SSL_exit", "byte_count <= 0");
        return cat2long(3, byte_count);
    }
    
    int n = 1;
    int data_size = byte_count;
    if (byte_count > MAX_BYTES) {
        n = byte_count / MAX_BYTES;
        if (byte_count % MAX_BYTES) n++;
        data_size = MAX_BYTES;
    }

    struct trace_t* trace = bpf_map_lookup_elem(&traces, &id);
    if (trace == NULL) {
        printk(LOG_TRACE, "SSL_exit", "trace is NULL");
        return 1;
    }

    if (!is_connected(trace)) {
        printk(LOG_TRACE, "SSL_exit", "trace is NOT connected");
        return 2;
    }

    u64 sslp = trace->ssl_conn;
    u32 sslc = trace->ssl_count;

    if (rw == READ_OP) {
        buf = (char *) (trace->rbuf);
    } else if (rw == WRITE_OP) {
        buf = (char *) (trace->wbuf);
    } else {
        printk(LOG_ERROR, "SSL_exit", "unsupported operation");
        return cat2long(6, rw);
    }

    for (int i = 0; i < min(n, MAX_ITERATIONS); i++) {
        buf = (char *) (buf + (i * MAX_BYTES));
        if (i == n - 1) {
            data_size = byte_count - (i * MAX_BYTES);
        }
        data_size = enforce_bounds_int(data_size, 0, MAX_BYTES);

        struct data_t *allotted;
        if (rw == READ_OP) {
            allotted = bpf_ringbuf_reserve(&reads, sizeof(struct data_t), 0);
            if (allotted == NULL) return 4;
        } else if (rw == WRITE_OP) {
            allotted = bpf_ringbuf_reserve(&writes, sizeof(struct data_t), 0);
            if (allotted == NULL) return 4;
        } else {
            printk(LOG_ERROR, "SSL_exit", "unsupported operation");
            return cat2long(6, rw);
        }

        allotted->pid = id;
        allotted->sslp = sslp;
        allotted->ts = ktime;
        allotted->len = data_size;
        errno = bpf_probe_read_user(allotted->data, data_size, buf);
        if (errno < 0) {
            bpf_ringbuf_discard(allotted, 0);
            return cat2long(4, (int) errno);
        }

        bpf_ringbuf_submit(allotted, 0);
    }

    return 0;
}

static int poison_well() {
    u64 ktime = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();

    struct trace_t* trace = bpf_map_lookup_elem(&traces, &id);
    if (trace == NULL) {
        printk(LOG_TRACE, "poison_well", "trace is NULL");
        return 1;
    }
    
    struct pill_t package = {
        .len = (u32) sizeof(u64),
        .pid  = id,
        .sslp = trace->ssl_conn,
        .sslc = trace->ssl_count,
        .ts   = ktime,
        .pill = (u64) POISON,
    };
    printk(LOG_DEBUG, "poison_well", "pill ready for ringbuf");

    u64 package_size = sizeof(struct pill_t);
    void *allotted = bpf_ringbuf_reserve(&reads, package_size, 0);
    if (allotted == NULL) return 2;
    int errno = bpf_probe_read_kernel(allotted, package_size, &package);
    if (errno) {
        bpf_ringbuf_discard(allotted, 0);
        return errno;
    }
    bpf_ringbuf_submit(allotted, 0);

    allotted = bpf_ringbuf_reserve(&writes, package_size, 0);
    if (allotted == NULL) return 2;
    errno = bpf_probe_read_kernel(allotted, package_size, &package);
    if (errno) {
        bpf_ringbuf_discard(allotted, 0);
        return errno;
    }
    bpf_ringbuf_submit(allotted, 0);

    return 0;
}


/**
 * 
 * User probes
 * 
 */

SEC("uprobe/SSL_connect")
int BPF_UPROBE(entry_ssl_connect, void* ssl) {
    const u64 id = bpf_get_current_pid_tgid();
    if (LOG_LEVEL >= LOG_TRACE) {
        const static char m[] = "[TRACE] [uprobe/SSL_connect    ]: attempting to establish a connection for PID %d.";
        bpf_trace_printk(m, sizeof(m), id);
    }

    if (init_trace((u64) ssl) == 0) {
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

    if (init_trace((u64) ssl) == 0) {
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
        printk(LOG_DEBUG, "uprobe/SSL_shutdown", "poison pill sent.");
    }
    if (delete_trace() == 0) {
        printk(LOG_DEBUG, "uprobe/SSL_shutdown", "trace deleted successfully.");
    }
    if (unlock_counter((u64) ssl) == 0) {
        printk(LOG_DEBUG, "uprobe/SSL_shutdown", "counter unlocked successfully.");
    }

    return 0;
}

SEC("uprobe/SSL_read")
int BPF_UPROBE(entry_ssl_read, void* ssl, void *buf, int num) {
    if (LOG_LEVEL >= LOG_DEBUG) {
        const static char m[] = "[DEBUG] [uprobe/SSL_read       ]: will attempt to read from buffer (%d bytes)";
        bpf_trace_printk(m, sizeof(m), num);
    }
    return (SSL_entry(ssl, buf, READ_OP));
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(entry_ssl_write, void* ssl, void *buf, int num) {
    if (LOG_LEVEL >= LOG_DEBUG) {
        const static char m[] = "[DEBUG] [uprobe/SSL_write      ]: will attempt to write to buffer (%d bytes)";
        bpf_trace_printk(m, sizeof(m), num);
    }
    return (SSL_entry(ssl, buf, WRITE_OP));
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

    long re = SSL_exit(ctx, READ_OP);
    const static char m1[] = "[DEBUG] [uretprobe/SSL_read    ]: SSL_exit rc: %d, errno: %d";
    bpf_trace_printk(m1, sizeof(m1), (int) re, re >> 32);

    return (int) re;
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

    long re = SSL_exit(ctx, WRITE_OP);
    const static char m1[] = "[DEBUG] [uretprobe/SSL_write   ]: SSL_exit rc: %d, errno: %d";
    bpf_trace_printk(m1, sizeof(m1), (int) re, re >> 32);

    return (int) re;
}

char __license[] SEC("license") = "GPL v2";
