#include <linux/bpf.h>
#include <asm/unistd.h>
#include <bpf/bpf_helpers.h>

#define PATH_BYTES 256
#define KIND_OPEN 1
#define KIND_CLOSE 2
#define KIND_DUP 3
#define KIND_EXEC 4
#define KIND_EXIT 5
#define KIND_FORK 6

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

struct sched_process_fork {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char parent_comm[16];
    int parent_pid;
    char child_comm[16];
    int child_pid;
};

struct pending_call {
    long syscall_nr;
    unsigned int kind;
    unsigned long args[4];
    unsigned int path_length;
    int path_error;
    char path[PATH_BYTES];
};

struct lifecycle_event {
    unsigned long long kernel_monotonic_ns;
    long long result;
    unsigned long long args[4];
    unsigned int pid;
    unsigned int tid;
    unsigned int related_pid;
    unsigned int kind;
    long syscall_nr;
    unsigned int path_length;
    int path_error;
    char path[PATH_BYTES];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, unsigned long long);
} target_cgroup_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned int);
    __type(value, struct pending_call);
} pending_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

#define COUNTER_MAP(name) \
struct { \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
    __uint(max_entries, 1); \
    __type(key, unsigned int); \
    __type(value, unsigned long long); \
} name SEC(".maps")

COUNTER_MAP(reserve_failures);
COUNTER_MAP(map_update_failures);
COUNTER_MAP(path_copy_failures);
COUNTER_MAP(path_truncations);

static __always_inline int is_target(void)
{
    unsigned int key = 0;
    unsigned long long *wanted = bpf_map_lookup_elem(&target_cgroup_id, &key);
    return wanted && *wanted == bpf_get_current_cgroup_id();
}

static __always_inline void increment_reserve_failure(void)
{
    unsigned int key = 0;

    unsigned long long *value = bpf_map_lookup_elem(&reserve_failures, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline void increment_map_update_failure(void)
{
    unsigned int key = 0;
    unsigned long long *value = bpf_map_lookup_elem(&map_update_failures, &key);
    if (value) __sync_fetch_and_add(value, 1);
}

static __always_inline void increment_path_copy_failure(void)
{
    unsigned int key = 0;
    unsigned long long *value = bpf_map_lookup_elem(&path_copy_failures, &key);
    if (value) __sync_fetch_and_add(value, 1);
}

static __always_inline void increment_path_truncation(void)
{
    unsigned int key = 0;
    unsigned long long *value = bpf_map_lookup_elem(&path_truncations, &key);
    if (value) __sync_fetch_and_add(value, 1);
}

static __always_inline int remember(struct trace_sys_enter *ctx, int path_arg, unsigned int kind)
{
    struct pending_call call = {};
    unsigned int tid;
    int copied;
    int index;

    if (!is_target())
        return 0;
    tid = (unsigned int)bpf_get_current_pid_tgid();
    call.syscall_nr = ctx->syscall_nr;
    call.kind = kind;
    for (index = 0; index < 4; index++)
        call.args[index] = ctx->args[index];
    if (path_arg >= 0) {
        copied = bpf_probe_read_user_str(call.path, sizeof(call.path),
                                         (void *)ctx->args[path_arg]);
        if (copied < 0) {
            call.path_error = copied;
            increment_path_copy_failure();
        } else if (copied > 0) {
            call.path_length = copied - 1;
            if (copied >= PATH_BYTES) increment_path_truncation();
        }
    }
    if (bpf_map_update_elem(&pending_calls, &tid, &call, BPF_ANY)) increment_map_update_failure();
    return 0;
}

static __always_inline int submit(struct trace_sys_exit *ctx)
{
    unsigned long long pid_tgid;
    unsigned int tid;
    struct pending_call *call;
    struct lifecycle_event *event;
    int index;

    if (!is_target())
        return 0;
    pid_tgid = bpf_get_current_pid_tgid();
    tid = (unsigned int)pid_tgid;
    call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (!call)
        return 0;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_reserve_failure();
        bpf_map_delete_elem(&pending_calls, &tid);
        return 0;
    }
    event->kernel_monotonic_ns = bpf_ktime_get_ns();
    event->result = ctx->ret;
    event->pid = pid_tgid >> 32;
    event->tid = tid;
    event->related_pid = 0;
    event->kind = call->kind;
    event->syscall_nr = call->syscall_nr;
    event->path_length = call->path_length;
    event->path_error = call->path_error;
    for (index = 0; index < 4; index++)
        event->args[index] = call->args[index];
    __builtin_memcpy(event->path, call->path, sizeof(event->path));
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&pending_calls, &tid);
    return 0;
}

static __always_inline int submit_simple(unsigned int kind, unsigned int related_pid)
{
    unsigned long long pid_tgid;
    struct lifecycle_event *event;
    if (!is_target())
        return 0;
    pid_tgid = bpf_get_current_pid_tgid();
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_reserve_failure();
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->kernel_monotonic_ns = bpf_ktime_get_ns();
    event->result = 0;
    event->pid = pid_tgid >> 32;
    event->tid = (unsigned int)pid_tgid;
    event->related_pid = related_pid;
    event->kind = kind;
    event->syscall_nr = -1;
    event->path_length = 0;
    event->path_error = 0;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int syscall_enter(struct trace_sys_enter *ctx)
{
    switch (ctx->syscall_nr) {
#ifdef __NR_open
    case __NR_open: return remember(ctx, 0, KIND_OPEN);
#endif
    case __NR_openat: return remember(ctx, 1, KIND_OPEN);
#ifdef __NR_openat2
    case __NR_openat2: return remember(ctx, 1, KIND_OPEN);
#endif
    case __NR_close: return remember(ctx, -1, KIND_CLOSE);
#ifdef __NR_close_range
    case __NR_close_range: return remember(ctx, -1, KIND_CLOSE);
#endif
    case __NR_dup: return remember(ctx, -1, KIND_DUP);
#ifdef __NR_dup2
    case __NR_dup2: return remember(ctx, -1, KIND_DUP);
#endif
    case __NR_dup3: return remember(ctx, -1, KIND_DUP);
    case __NR_fcntl:
        if (ctx->args[1] == 0 || ctx->args[1] == 1030)
            return remember(ctx, -1, KIND_DUP);
        return 0;
    default: return 0;
    }
}

SEC("tracepoint/raw_syscalls/sys_exit")
int syscall_exit(struct trace_sys_exit *ctx)
{
    return submit(ctx);
}

SEC("tracepoint/sched/sched_process_exec") int process_exec(void *ctx) { return submit_simple(KIND_EXEC, 0); }
SEC("tracepoint/sched/sched_process_exit") int process_exit(void *ctx) { return submit_simple(KIND_EXIT, 0); }
SEC("tracepoint/sched/sched_process_fork") int process_fork(struct sched_process_fork *ctx) { return submit_simple(KIND_FORK, ctx->child_pid); }

char LICENSE[] SEC("license") = "GPL";
