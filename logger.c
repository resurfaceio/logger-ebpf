//go:build ignore

// © 2025 Graylog, Inc.

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>


#define LOG_DISABLED        0  // Disable all trace logging.
#define LOG_ERROR           1  // Log fatal errors only.
#define LOG_WARN            2  // Log fatal and non-fatal errors.
#define LOG_INFO            3  // Log errors and basic non-error details.
#define LOG_DEBUG           4  // Log errors and non-error details.
#define LOG_TRACE           5  // Log all details.

#define READ_OP             0
#define WRITE_OP            1
#define CONNECT_OP          0
#define ACCEPT_OP           1

#define ZERO                0
#define MAX_U32_VALUE       0xFFFFFFFF

#define MAX_BYTES           512      // max 512   B per iteration
#define MAX_ITERATIONS      512      // max 256 kiB per HTTPS payload
#define RINGBUF_SIZE        16777216 // max  16 MiB per ringbuf (32 MiB in total for both req and resp)

#define POISON              0x8D0003048D0304F0
#define COUNTER_LOCK        MAX_U32_VALUE
#define LOG_LEVEL           LOG_TRACE

/**
 * 
 * Data structures
 * 
 */

/**
 * Trace stash
 * Description: holds the value of the *SSL used to establish a given TLS connection
 *              on top of the underlying network connection carrying each HTTP message.
 *              In addition, this struct keeps track of its initialization time as a 
 *              u64 timestamp, as well as buffer references for SSL_entry/SSL_exit.
 * 
 * [  ssl (64) | created_at (64) | rbuf (64) | wbuf (64) ]
 */
struct stash_t {
    u64 ssl;
    u64 last_modified;
    uintptr_t rbuf;
    uintptr_t wbuf;
};

/**
 * Data package
 * Description: package with char data to be sent to application in userspace through eBPF maps.
 * [ ts (64) | pid_tgid (64) | ssl_ptr (64) | ssl_count (32) | data_len (32) | data (MAX_BYTES) ]
 */
struct data_t {
    u64 ts;
    u64 pid;
    u64 ssl_p;
    u32 ssl_c;
    u32 len;
    char data[MAX_BYTES];
};

/**
 * Pill package
 * Description: package with a single u64 member to be sent to application in userspace through eBPF maps.
 * [ ts (64) | pid_tgid (64) | ssl_ptr (64) | ssl_count (32) | pill_len (32) | pill (64) ]
 */
struct pill_t {
    u64 ts;
    u64 pid;
    u64 ssl_p;
    u32 ssl_c;
    u32 len;
    u64 pill;
};

/**
 * SSL counter
 * Description: keeps track of the number of times a given *SSL memory address has been
 *              (re)used, by updating a counter each time it is used in a new connection.
 *              A flag lock is put in place throughout the TLS connection lifecycle; i.e.
 *              from SSL_connect/accept calls, to SSL_read/write, and finally SSL_shutdown.
 *              Once SSL_free is called, the corresponding counter is unlocked. Staleness
 *              is determined using the last time the counter lock state was updated.
 * [ count (32) | lock (32) | last_updated (64) | rbuf (64) | wbuf (64) ]
 */
struct counter_t {
    u32 count;
    u32 lock;
    u64 last_updated;
    
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
    __type(value, struct stash_t);
    __uint(max_entries, 10000);
} stashes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u128);
    __type(value, struct counter_t);
    __uint(max_entries, 10000);
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
    return a < b ? a : b;
}

/**
 * @name enforce_bounds
 * @brief Constrains an long integer within a given range.
 * @param n long integer to constrain.
 * @param lower smallest possible value in the allowed range.
 * @param upper largest possible value in the allowed range.
 * @return n if lower < n < upper. Otherwise, the nearest bound is enforced.
 */
static int enforce_bounds(int n, int lower, int upper) {
    if (n < lower) n = lower;
    if (n > upper) n = upper;
    return n;
}

/**
 * @name cat2long
 * @brief Concatenate two integers into a long integer.
 * @param lower integer to concatenate in the lower half of the return value.
 * @param upper integer to concatenate in the upper half of the return value.
 * @return long integer of the form: [ upper | lower ]
 */
static long cat2long(int lower, int upper) {
    long c = upper;
    c <<= (sizeof(int) * 8);
    return c | lower;
}

/**
 * @name get_joined_id
 * @brief Concatenate PID_TGID and *SSL into a u128.
 * @param ssl *SSL connection as a u64 integer.
 * @return joined identifier of the form: [ pid_tgid | ssl ]
 */
static u128 get_joined_id(u64 ssl) {
    u128 id = bpf_get_current_pid_tgid();
    id <<= (sizeof(u64) * 8);
    return id | ssl;
}

/**
 * @name is_locked
 * @brief Check counter lock state.
 * @param c struct counter_t* counter with lock to be checked.
 * @return 1 if locked, 0 if not locked.
 */
static int is_locked(struct counter_t *c) {
    return c->lock == COUNTER_LOCK;
}

/**
 * 
 * Main functions
 * 
 */


/**
 * @name init_count
 * @brief Initializes a counter with a given SSL memory address value.
 * 
 * @param ssl_p *SSL connection to trace.
 * @return Propagates return value from bpf_map_update_elem (0 on success, or a negative value in case of failure).
 * @retval 1 if counter already exists in counts map.
 */
 static int init_count(void* ssl_p) {
     u64 ktime = bpf_ktime_get_ns();
     u128 jid = get_joined_id((u64) ssl_p);

    struct counter_t *counter = bpf_map_lookup_elem(&counts, &jid);
    if (counter != NULL) return 1;

    struct counter_t new_counter = {
        .count        = (u32) ZERO,
        .lock         = (u32) COUNTER_LOCK,
        .last_updated = ktime,
    };
    return (int) bpf_map_update_elem(&counts, &jid, &new_counter, BPF_NOEXIST);
 }

 /**
 * @name up_count
 * @brief Increases the count for a given *SSL, if counter is unlocked. Does nothing if counter is locked.
 * 
 * @param ssl *SSL connection to trace.
 * @return Current count if positive, or propagated return value from bpf_map_update_elem (0 on success, or a negative value in case of failure).
 */
static int up_count(void* ssl_p) {
    u128 jid = get_joined_id((u64) ssl_p);

    struct counter_t *counter = bpf_map_lookup_elem(&counts, &jid);
    if (counter == NULL) return -1;

    if (!is_locked(counter)) {
        counter->count++;
        counter->lock = COUNTER_LOCK;
//        int errno = (int) bpf_map_update_elem(&counts, &jid, counter, BPF_EXIST);
//        if (errno < 0) return errno;
    }
    
    return counter->count;
}

 /**
 * @name unlock_counter
 * @brief Unlocks the counter for a given *SSL.
 * 
 * @param ssl *SSL Connection with counter to be unlocked.
 * @return Propagates return value from bpf_map_delete_elem (0 on success, or a negative value in case of failure).
 * @retval 1 if count does not exist in map.
 */
static int unlock_counter(void* ssl_p) {
    u128 jid = get_joined_id((u64) ssl_p);

    struct counter_t *counter = bpf_map_lookup_elem(&counts, &jid);
    if (counter == NULL) return 1;

    if (is_locked(counter)) {
        counter->lock = ZERO;
        counter->last_updated = bpf_ktime_get_ns();
//        return (int) bpf_map_update_elem(&counts, &jid, counter, BPF_EXIST);
    }

    return is_locked(counter);
}

/**
 * @name delete_counter
 * @brief Deletes the existing counter for a given *SSL, regardless of lock state.
 * 
 * @return Propagates return value from bpf_map_delete_elem (0 on success, or a negative value in case of failure).
 */
static int delete_counter(void *ssl_p) {
    u64 ssl = (u64) ssl_p;

    struct counter_t *counter = bpf_map_lookup_elem(&counts, &ssl);
    if (counter == NULL) return 0;

    return (int) bpf_map_delete_elem(&counts, &ssl);
}

/**
 * @name init_stash
 * @brief Initializes a stash with the current given pid+tgid, and a given SSL memory address value.
 * 
 * @param ssl *SSL Connection to trace.
 * @return Propagates return value from bpf_map_update_elem (0 on success, or a negative value in case of failure).
 */
static long init_stash(void* ssl) {
    u64 ktime = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();

    int rc = init_count(ssl);
    if (rc == 1) {
        if (up_count(ssl) < 0) return 2;
        printk(LOG_DEBUG, "init_stash", "counter is LOCKED.");
    } else if (rc == 0) {
        printk(LOG_DEBUG, "init_stash", "new counter initialized sucessfully.");
    } else {
        return cat2long(3, rc);
    }

    struct stash_t* stash = bpf_map_lookup_elem(&stashes, &id);
    if (stash != NULL) return 1;

    struct stash_t new_stash = {
        .ssl           = (u64) ssl,
        .last_modified = (u64) ktime,
        .rbuf          = (uintptr_t) ZERO,
        .wbuf          = (uintptr_t) ZERO,
    };
    stash = &new_stash;

    return bpf_map_update_elem(&stashes, &id, stash, BPF_NOEXIST);
}

/**
 * @name delete_stash
 * @brief Deletes the existing trace for the current pid+tgid.
 * 
 * @return Propagates return value from bpf_map_delete_elem (0 on success, or a negative value in case of failure).
 */
static long delete_stash() {
    u64 id = bpf_get_current_pid_tgid();
    return bpf_map_delete_elem(&stashes, &id);
}

/**
 * @name SSL_entry 
 * @brief Stashes a reference to a given read/write data buffer buf.
 * 
 * To be used at SSL_read/SSL_write function entrypoints.
 * 
 * @param ssl_p Pointer to SSL struct.
 * @param buf   Pointer to read/write data buffer
 * @param rw    Flag to indicate type of operation
 * 
 * @return Propagates return value from bpf_map_update_elem (0 on success, or a negative value in case of failure).
 * @retval 0 if the reference was stashed successfully.
 * @retval 1 if stash is NULL as the underlying TLS connection has not been established.
 * @retval 2 if count is NULL as the underlying TLS connection has not been recognized (could not init new counter).
 * @retval 3 if count is NULL as the underlying TLS connection has not been recognized (could not fetch newly initd counter).
 * @retval 4 if count is NOT LOCKED as the underlying TLS connection has not been established.
 * @retval 5 if the operation specified by rw is not supported.
 */
static int SSL_entry(void* ssl_p, void *buf, int rw) {
    u64 id = bpf_get_current_pid_tgid();

    // bpf_trace_printk("[TEST] [SSL_entry] buf address: %p", 35, buf);

    struct stash_t* stash = bpf_map_lookup_elem(&stashes, &id);
    if (stash == NULL) return 1;

    u64 ssl = (u64) ssl_p;
    if (stash->ssl != ssl) {
        printk(LOG_DEBUG, "SSL_entry", "stash->ssl != ssl provided. Trying to reassign to existing counter...");
        stash->ssl = ssl;
    }

    u128 jid = get_joined_id(ssl);
    struct counter_t* counter = bpf_map_lookup_elem(&counts, &jid);
    if (counter == NULL) {
        printk(LOG_DEBUG, "SSL_entry", "counter is NULL. Trying to initialize new counter...");
        if (init_count(ssl_p) < 0) return 2;

        counter = bpf_map_lookup_elem(&counts, &jid);
        if (counter == NULL) return 3;
    }

    if (!is_locked(counter)) return 4;

    if (rw == READ_OP) {
        stash->rbuf = (uintptr_t) buf;
    } else if (rw == WRITE_OP) {
        stash->wbuf = (uintptr_t) buf;
    } else {
        return 5;
    }
    
//    return bpf_map_update_elem(&stashes, &id, stash, BPF_EXIST);
    return 0;
}

/**
 * @name SSL_exit
 * @brief Retrieves read/written data from stashed buffer,
 *        packages it using its corresponding identifier, and
 *        submits the data to the appropriate output ringbuf.
 * 
 * To be used at SSL_read/SSL_write function return points.
 * 
 * @param ctx Pointer to eBPF context variable
 * @param rw  Flag to indicate type of operation
 * 
 * @return Corresponding retval (see below) concatenated with more context, such as byte_count
 *         or errno, in the form: [ retval (32) | errno (32) ]
 * 
 * @retval 0 if data was successfully retrieved from buffer and submitted to output ringbuf.
 * @retval 1 if the number of bytes read/written specified by the function rc is invalid.
 * @retval 2 if stash is NULL as the underlying TLS connection has not been established.
 * @retval 3 if count is NULL as the underlying TLS connection has not been recognized.
 * @retval 4 if count is NOT LOCKED as the underlying TLS connection has not been established.
 * @retval 5 if data could not be read from the stashed buffer.
 * @retval 6 if data could not be submitted to the output ringbuf.
 * @retval 7 if the operation specified by rw is not supported.
 */
static long SSL_exit(struct pt_regs *ctx, int rw) {
    u64 ktime = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    char *buf;
    long errno;

    int byte_count = PT_REGS_RC(ctx);
    if (byte_count <= 0) return cat2long(1, byte_count);
    
    int n = 1;
    int data_size = byte_count;
    if (byte_count > MAX_BYTES) {
        n = byte_count / MAX_BYTES;
        if (byte_count % MAX_BYTES) n++;
        data_size = MAX_BYTES;
    }

    struct stash_t* stash = bpf_map_lookup_elem(&stashes, &id);
    if (stash == NULL) return 2;

    u64 ssl_p = stash->ssl;

    u128 jid = get_joined_id(ssl_p);
    struct counter_t *counter = bpf_map_lookup_elem(&counts, &jid);
    if (counter == NULL) return 3;

    if (!is_locked(counter)) return 4;

    u32 ssl_c = counter->count;

    if (rw == READ_OP) {
        buf = (char *) (stash->rbuf);
    } else if (rw == WRITE_OP) {
        buf = (char *) (stash->wbuf);
    } else {
        return cat2long(7, rw);
    }

    // bpf_trace_printk("[TEST] [SSL_exit ] buf address: %p", 35, buf);

    for (int i = 0; i < min(n, MAX_ITERATIONS); i++) {
        buf = (char *) (buf + (i * MAX_BYTES));
        if (i == n - 1) {
            data_size = byte_count - (i * MAX_BYTES);
        }
        data_size = enforce_bounds(data_size, 0, MAX_BYTES);

        struct data_t *allotted;
        if (rw == READ_OP) {
            allotted = bpf_ringbuf_reserve(&reads, sizeof(struct data_t), 0);
            if (allotted == NULL) return 5;
        } else if (rw == WRITE_OP) {
            allotted = bpf_ringbuf_reserve(&writes, sizeof(struct data_t), 0);
            if (allotted == NULL) return 5;
        } else {
            return cat2long(7, rw);
        }

        allotted->pid = id;
        allotted->ssl_p = ssl_p;
        allotted->ssl_c = ssl_c;
        allotted->ts = ktime;
        allotted->len = data_size;
        errno = bpf_probe_read_user(allotted->data, data_size, buf);
        if (errno < 0) {
            bpf_ringbuf_discard(allotted, 0);
            return cat2long(6, (int) errno);
        }

        bpf_ringbuf_submit(allotted, 0);
    }

    return 0;
}

/**
 * @name poison_well 
 * @brief Submits poison pill to all output ringbufs.
 * 
 * To be used at SSL_shutdown entrypoint.
 * 
 * @return Propagates return value from bpf_map_read_kernel (0 on success, or a negative value in case of failure).
 * @retval 0 if the pill was successfully submitted to all output ringbufs.
 * @retval 1 if the underlying TLS connection has not been recognized (count is NULL).
 * @retval 2 if the pill could not be submitted to any output ringbuf.
 */
static int poison_well(void* ssl_p) {
    u64 ktime = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u64 ssl = (u64) ssl_p;

    struct pill_t package = {
        .len   = (u32) sizeof(u64),
        .pid   = id,
        .ts    = ktime,
        .ssl_p = ssl,
        .pill  = (u64) POISON,
    };

    u128 jid = get_joined_id(ssl);
    struct counter_t *counter = bpf_map_lookup_elem(&counts, &jid);
    if (counter == NULL) {
        printk(LOG_DEBUG, "poison_well", "counter is NULL.");
        return 1;
    }

    if (!is_locked(counter)) {
        printk(LOG_DEBUG, "poison_well", "pill has been sent already. Nothing to do.");
        return 0;
    }

    package.ssl_c = counter->count;

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
 * @name connect_accept_entry 
 * @brief Initializes a stash corresponding to the current pid+tgid.
 * 
 * To be used at SSL_connect/SSL_accept function entrypoints.
 * 
 * @param ssl  Pointer to SSL struct.
 * @param ca   lag to indicate type of operation.
 * 
 * @return 0 wheter intialization succeeds or not. Instead, check trace logs at runtime.
 */
static int connect_accept_entry(void* ssl, int ca) {
    char *label = ca == CONNECT_OP ? "uprobe/SSL_connect" : ca == ACCEPT_OP ? "uprobe/SSL_accept " : "???";
    if (LOG_LEVEL >= LOG_TRACE) {
        const u64 id = bpf_get_current_pid_tgid();
        const static char m[] = "[TRACE] [%s    ]: attempting to carry out TLS/SSL handshake for PID %d.";
        bpf_trace_printk(m, sizeof(m), label, id);
    }

    long re = init_stash(ssl);
    switch ((int) re)
    {
    case 0:
        printk(LOG_DEBUG, label, "stash initialized successfully.");
        break;
    case 1:
        printk(LOG_DEBUG, label, "stash already initialized. Nothing to do.");
        break;
    case 2:
        printk(LOG_DEBUG, label, "failed to initialize stash; counter is NULL");
        break;
    case 3:
        if (LOG_LEVEL >= LOG_DEBUG) {
            const static char m[] = "[DEBUG] [%s   ]: failed to initialize stash; errno: %d.";
            bpf_trace_printk(m, sizeof(m), label, re >> 32);
        }
    default:
        break;
    }

    return 0;
}

/**
 * @name connect_accept_exit
 * @brief Deletes the stash corresponding to the current pid+tgid.
 * 
 * To be used at SSL_connect/SSL_accept function return points.
 * 
 * @param ssl  Pointer to SSL struct.
 * @param ca   lag to indicate type of operation.
 * 
 * @return 0 wheter deletion succeeds or not. Instead, check trace logs at runtime.
 */
static int connect_accept_exit(int rc, int ca) {
    char *label = ca == CONNECT_OP ? "uretprobe/SSL_connect" : ca == ACCEPT_OP ? "uretprobe/SSL_accept " : "???";
    if (LOG_LEVEL >= LOG_TRACE) {
        const u64 id = bpf_get_current_pid_tgid();
        if (rc == 1) {
            const static char m[] = "[TRACE] [%s ]: TLS/SSL handshake successfully completed for PID %d.";
            bpf_trace_printk(m, sizeof(m), label, id);
        } else {
            const static char m[] = "[TRACE] [%s ]: failed to perform a TLS/SSL handshake for PID %d. Return code: %d";
            bpf_trace_printk(m, sizeof(m), label, id, rc);
        }
    }

    return 0;
}


/**
 * 
 * User probes
 * 
 */

SEC("uprobe/SSL_connect")
int BPF_UPROBE(entry_ssl_connect, void* ssl) {
    return connect_accept_entry(ssl, CONNECT_OP);
}

SEC("uretprobe/SSL_connect")
int BPF_URETPROBE(ret_ssl_connect, int rc) {
    return connect_accept_exit(rc, CONNECT_OP);
}

SEC("uprobe/SSL_accept")
int BPF_UPROBE(entry_ssl_accept, void* ssl) {
    return connect_accept_entry(ssl, ACCEPT_OP);
}

SEC("uretprobe/SSL_accept")
int BPF_URETPROBE(ret_ssl_accept, int rc) {
    return connect_accept_exit(rc, ACCEPT_OP);
}

SEC("uprobe/SSL_shutdown")
int BPF_UPROBE(entry_ssl_shutdown, void* ssl) {
    if (LOG_LEVEL >= LOG_TRACE) {
        const u64 id = bpf_get_current_pid_tgid();
        const static char m[] = "[TRACE] [uprobe/SSL_shutdown   ]: attempting to shutdown an active TLS/SSL connection for PID %d.";
        bpf_trace_printk(m, sizeof(m), id);
    }

    if (poison_well(ssl) == 0) {
        printk(LOG_DEBUG, "uprobe/SSL_shutdown", "poison pill sent.");
    }

    return 0;
}

SEC("uprobe/SSL_free")
int BPF_UPROBE(entry_ssl_free, void* ssl) {
    if (unlock_counter(ssl) == 0) {
        printk(LOG_DEBUG, "uprobe/SSL_free", "counter unlocked successfully.");
    } else if (delete_counter(ssl) == 0) {
        printk(LOG_DEBUG, "uprobe/SSL_free", "failed to unlock counter. An attempt to delete counter was successful.");
    } else {
        printk(LOG_DEBUG, "uprobe/SSL_free", "failed to both unlock and delete counter.");
    }

    return 0;
}

SEC("uprobe/SSL_read")
int BPF_UPROBE(entry_ssl_read, void* ssl, void *buf, int num) {
    if (LOG_LEVEL >= LOG_TRACE) {
        const static char m[] = "[TRACE] [uprobe/SSL_read       ]: will attempt to read from buffer (%d bytes)";
        bpf_trace_printk(m, sizeof(m), num);
    }

    int rc = SSL_entry(ssl, buf, READ_OP);
    if (rc == 1) {
        printk(LOG_DEBUG, "SSL_read", "stash is NULL");
    } else if (rc == 2) {
        printk(LOG_DEBUG, "SSL_read", "could initialize new counter.");
    } else if (rc == 3) {
        printk(LOG_DEBUG, "SSL_read", "could not fetch newly initialized counter.");
    } else if (rc == 4) {
        printk(LOG_DEBUG, "SSL_read", "counter is NOT LOCKED.");
    } else if (rc == 5) {
        printk(LOG_ERROR, "SSL_read", "unsupported operation");
    }

     return 0;
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(entry_ssl_write, void* ssl, void *buf, int num) {
    if (LOG_LEVEL >= LOG_TRACE) {
        const static char m[] = "[TRACE] [uprobe/SSL_write      ]: will attempt to write to buffer (%d bytes)";
        bpf_trace_printk(m, sizeof(m), num);
    }

    int rc = SSL_entry(ssl, buf, WRITE_OP);
    if (rc == 1) {
        printk(LOG_DEBUG, "SSL_write", "stash is NULL");
    } else if (rc == 2) {
        printk(LOG_DEBUG, "SSL_write", "could initialize new counter.");
    } else if (rc == 3) {
        printk(LOG_DEBUG, "SSL_write", "could not fetch newly initialized counter.");
    } else if (rc == 4) {
        printk(LOG_DEBUG, "SSL_write", "counter is NOT LOCKED.");
    } else if (rc == 5) {
        printk(LOG_ERROR, "SSL_write", "unsupported operation");
    }

     return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ret_ssl_read, int n) {
    if (LOG_LEVEL >= LOG_TRACE) {
        const static char m[] = "[TRACE] [uretprobe/SSL_read    ]: read %d bytes!";
        if (n > 0) {
            bpf_trace_printk(m, sizeof(m), n);
        } else {
            bpf_trace_printk(m, sizeof(m), 0);
        }
    }

    long re = SSL_exit(ctx, READ_OP);
    int rc = (int) re;
    int err = re >> 32;

    if (LOG_LEVEL >= LOG_DEBUG) {
        const static char m0[] = "[DEBUG] [uretprobe/SSL_read    ]: SSL_exit: %serrno: %d";
        const static char m1[] = "[DEBUG] [uretprobe/SSL_read    ]: SSL_exit: byte_count: %d";
        if (rc == 1 && LOG_LEVEL >= LOG_TRACE) {
            bpf_trace_printk(m1, sizeof(m1), err);
        } else if (rc == 2) {
            printk(LOG_DEBUG, "SSL_read", "SSL_exit: stash is NULL.");
        } else if (rc == 3) {
            printk(LOG_DEBUG, "SSL_read", "SSL_exit: count is NULL.");
        } else if (rc == 4) {
            printk(LOG_DEBUG, "SSL_read", "SSL_exit: count is NOT LOCKED.");
        } else if (rc == 5) {
            bpf_trace_printk(m0, sizeof(m0), "data could not be read from stashed buffer: ", err);
        } else if (rc == 6) {
            bpf_trace_printk(m0, sizeof(m0), "data could not be submitted to output buffer: ", err);
        } else if (rc == 7) {
            bpf_trace_printk(m0, sizeof(m0), "unsupported operation: ", err);
        } else {
            bpf_trace_printk(m0, sizeof(m0), err);
        }
    }

    return 0;
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
    int rc = (int) re;
    int err = re >> 32;

    if (LOG_LEVEL >= LOG_DEBUG) {
        const static char m0[] = "[DEBUG] [uretprobe/SSL_write   ]: SSL_exit: %serrno: %d";
        const static char m1[] = "[DEBUG] [uretprobe/SSL_write   ]: SSL_exit: byte_count: %d <= 0";
        if (rc == 1 && LOG_LEVEL >= LOG_TRACE) {
            bpf_trace_printk(m1, sizeof(m1), err);
        } else if (rc == 2) {
            printk(LOG_DEBUG, "SSL_write", "SSL_exit: stash is NULL.");
        } else if (rc == 3) {
            printk(LOG_DEBUG, "SSL_write", "SSL_exit: count is NULL.");
        } else if (rc == 4) {
            printk(LOG_DEBUG, "SSL_write", "SSL_exit: count is NOT LOCKED.");
        } else if (rc == 5) {
            bpf_trace_printk(m0, sizeof(m0), "data could not be read from stashed buffer: ", err);
        } else if (rc == 6) {
            bpf_trace_printk(m0, sizeof(m0), "data could not be submitted to output buffer: ", err);
        } else if (rc == 7) {
            bpf_trace_printk(m0, sizeof(m0), "unsupported operation: ", err);
        } else {
            bpf_trace_printk(m0, sizeof(m0), err);
        }
    }

    return 0;
}

char __license[] SEC("license") = "GPL v2";
