#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define PREFIX_BYTES 16384
#define KIND_WRITE 1
#define KIND_READ 2

struct trace_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long syscall_nr;
    unsigned long args[6];
};

struct trace_sys_exit {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long syscall_nr;
    long ret;
};

struct pending_io {
    unsigned long long user_buffer;
    unsigned long long requested_count;
    int fd;
};

struct io_event {
    unsigned long long kernel_monotonic_ns;
    unsigned long long requested_count;
    long long actual_count;
    unsigned int pid;
    unsigned int tid;
    int fd;
    unsigned int kind;
    unsigned int captured_bytes;
    int capture_error;
    unsigned char data[PREFIX_BYTES];
};

struct bpf_map_def SEC("maps") target_pid = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(unsigned int),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") pending_reads = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct pending_io),
    .max_entries = 128,
};

struct bpf_map_def SEC("maps") pending_writes = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct pending_io),
    .max_entries = 128,
};

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1 << 20,
};

struct bpf_map_def SEC("maps") reserve_failures = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(unsigned long long),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") capture_failures = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(unsigned long long),
    .max_entries = 1,
};

static __always_inline int is_target(void)
{
    unsigned int key = 0;
    unsigned int *wanted = bpf_map_lookup_elem(&target_pid, &key);
    unsigned int current = bpf_get_current_pid_tgid() >> 32;
    return wanted && *wanted == current;
}

static __always_inline void increment_counter(void *map)
{
    unsigned int key = 0;
    unsigned long long *value = bpf_map_lookup_elem(map, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline int remember_io(
    void *map, struct trace_sys_enter *ctx)
{
    unsigned int tid;
    struct pending_io pending = {};

    if (!is_target())
        return 0;
    tid = (unsigned int)bpf_get_current_pid_tgid();
    pending.fd = (int)ctx->args[0];
    pending.user_buffer = ctx->args[1];
    pending.requested_count = ctx->args[2];
    bpf_map_update_elem(map, &tid, &pending, BPF_ANY);
    return 0;
}

static __always_inline int submit_io(
    void *map, struct trace_sys_exit *ctx, unsigned int kind)
{
    unsigned long long pid_tgid;
    unsigned long long wanted;
    unsigned int tid;
    unsigned int captured;
    struct pending_io *pending;
    struct io_event *event;

    if (!is_target())
        return 0;
    pid_tgid = bpf_get_current_pid_tgid();
    tid = (unsigned int)pid_tgid;
    pending = bpf_map_lookup_elem(map, &tid);
    if (!pending)
        return 0;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_counter(&reserve_failures);
        bpf_map_delete_elem(map, &tid);
        return 0;
    }
    event->kernel_monotonic_ns = bpf_ktime_get_ns();
    event->requested_count = pending->requested_count;
    event->actual_count = ctx->ret;
    event->pid = pid_tgid >> 32;
    event->tid = tid;
    event->fd = pending->fd;
    event->kind = kind;
    event->captured_bytes = 0;
    event->capture_error = 0;
    wanted = ctx->ret > 0 ? (unsigned long long)ctx->ret : 0;
    if (wanted > pending->requested_count)
        wanted = pending->requested_count;
    if (wanted > PREFIX_BYTES)
        wanted = PREFIX_BYTES;
    captured = (unsigned int)wanted;
    if (captured > 0) {
        int error = bpf_probe_read_user(
            event->data, captured, (void *)pending->user_buffer);
        if (error) {
            event->capture_error = error;
            captured = 0;
            increment_counter(&capture_failures);
        }
    }
    event->captured_bytes = captured;
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(map, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int enter_read(struct trace_sys_enter *ctx)
{
    return remember_io(&pending_reads, ctx);
}

SEC("tracepoint/syscalls/sys_exit_read")
int exit_read(struct trace_sys_exit *ctx)
{
    return submit_io(&pending_reads, ctx, KIND_READ);
}

SEC("tracepoint/syscalls/sys_enter_write")
int enter_write(struct trace_sys_enter *ctx)
{
    return remember_io(&pending_writes, ctx);
}

SEC("tracepoint/syscalls/sys_exit_write")
int exit_write(struct trace_sys_exit *ctx)
{
    return submit_io(&pending_writes, ctx, KIND_WRITE);
}

char LICENSE[] SEC("license") = "GPL";
