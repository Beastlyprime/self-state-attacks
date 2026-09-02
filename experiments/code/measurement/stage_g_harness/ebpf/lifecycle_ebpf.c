#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PATH_BYTES 256
#define MAX_LINKS 64

struct lifecycle_event {
    uint64_t kernel_monotonic_ns;
    int64_t result;
    uint64_t args[4];
    uint32_t pid;
    uint32_t tid;
    uint32_t related_pid;
    uint32_t kind;
    int64_t syscall_nr;
    uint32_t path_length;
    int32_t path_error;
    char path[PATH_BYTES];
};

struct context {
    FILE *raw;
    uint64_t events;
    uint64_t recovered_path_copy_failures;
    uint64_t unresolved_path_failures;
};
static volatile sig_atomic_t stop_requested;
static int libbpf_log(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}


static uint64_t clock_ns(clockid_t id)
{
    struct timespec value;
    if (clock_gettime(id, &value) != 0) return 0;
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static void stop_handler(int signal_number) { (void)signal_number; stop_requested = 1; }

static void json_string(FILE *out, const char *value, uint32_t length)
{
    uint32_t i;
    fputc('"', out);
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)value[i];
        if (c == '"' || c == '\\') { fputc('\\', out); fputc(c, out); }
        else if (c >= 0x20 && c < 0x7f) fputc(c, out);
        else fprintf(out, "\\u%04x", c);
    }
    fputc('"', out);
}

static const char *kind_name(uint32_t kind)
{
    switch (kind) {
    case 1: return "open"; case 2: return "close"; case 3: return "dup";
    case 4: return "exec"; case 5: return "exit"; case 6: return "fork";
    default: return "unknown";
    }
}

static int handle_event(void *opaque, void *data, size_t size)
{
    struct context *context = opaque;
    const struct lifecycle_event *event = data;
    uint32_t path_length;
    char proc_path[64], resolved_path[PATH_MAX];
    const char *resolution_method = NULL;
    ssize_t resolved_length = -1;
    int proc_fd_error = 0;
    if (size < sizeof(*event)) return 0;
    path_length = event->path_length > PATH_BYTES ? PATH_BYTES : event->path_length;
    if (event->kind == 1 && event->result >= 0) {
        if (path_length > 0 && event->path[0] == '/') {
            memcpy(resolved_path, event->path, path_length);
            resolved_path[path_length] = '\0';
            resolved_length = path_length;
            resolution_method = "ebpf_open_exit";
        } else {
            snprintf(proc_path, sizeof(proc_path), "/proc/%u/fd/%lld",
                     event->pid, (long long)event->result);
            resolved_length = readlink(proc_path, resolved_path, sizeof(resolved_path) - 1);
            if (resolved_length >= 0) {
                resolved_path[resolved_length] = '\0';
                resolution_method = "proc_fd";
            } else {
                proc_fd_error = errno;
            }
        }
    }
    if (event->path_error < 0) {
        if (resolved_length >= 0) context->recovered_path_copy_failures++;
        else context->unresolved_path_failures++;
    } else if (event->kind == 1 && event->result >= 0 && resolved_length < 0) {
        context->unresolved_path_failures++;
    }
    fprintf(context->raw,
        "{\"record_type\":\"syscall_lifecycle\",\"source\":\"ebpf\","
        "\"timestamp_realtime_ns\":%llu,\"timestamp_monotonic_ns\":%llu,"
        "\"kernel_monotonic_ns\":%llu,\"kind\":\"%s\","
        "\"pid\":%u,\"tid\":%u,\"related_pid\":%u,\"syscall_number\":%lld,"
        "\"result\":%lld,\"args\":[%llu,%llu,%llu,%llu],"
        "\"path_error\":%d,\"path_truncated\":%s,\"path\":",
        (unsigned long long)clock_ns(CLOCK_REALTIME),
        (unsigned long long)clock_ns(CLOCK_MONOTONIC),
        (unsigned long long)event->kernel_monotonic_ns, kind_name(event->kind),
        event->pid, event->tid, event->related_pid, (long long)event->syscall_nr,
        (long long)event->result,
        (unsigned long long)event->args[0], (unsigned long long)event->args[1],
        (unsigned long long)event->args[2], (unsigned long long)event->args[3],
        event->path_error, event->path_length >= PATH_BYTES - 1 ? "true" : "false");
    json_string(context->raw, event->path, path_length);
    fputs(",\"resolved_path\":", context->raw);
    if (resolved_length >= 0)
        json_string(context->raw, resolved_path, (uint32_t)resolved_length);
    else
        fputs("null", context->raw);
    fputs(",\"resolution_method\":", context->raw);
    if (resolution_method)
        json_string(context->raw, resolution_method, (uint32_t)strlen(resolution_method));
    else
        fputs("null", context->raw);
    fprintf(context->raw, ",\"proc_fd_error\":%d", proc_fd_error);
    fputs("}\n", context->raw);
    fflush(context->raw);
    context->events++;
    return 0;
}

static uint64_t per_cpu_counter(int fd)
{
    uint32_t key = 0;
    int cpus = libbpf_num_possible_cpus(), i;
    uint64_t total = 0, *values;
    if (fd < 0 || cpus <= 0) return 0;
    values = calloc((size_t)cpus, sizeof(*values));
    if (!values) return 0;
    if (bpf_map_lookup_elem(fd, &key, values) == 0)
        for (i = 0; i < cpus; i++) total += values[i];
    free(values);
    return total;
}

int main(int argc, char **argv)
{
    struct bpf_object *object = NULL;
    struct bpf_program *program;
    struct bpf_link *links[MAX_LINKS] = {};
    struct ring_buffer *ring = NULL;
    struct context context = {};
    uint32_t key = 0;
    uint64_t target, started_wall = 0, started_mono = 0, stopped_wall, stopped_mono;
    int target_map = -1, event_map = -1, reserve_map = -1, link_count = 0, result = 1;
    int update_map = -1, copy_map = -1, truncation_map = -1;
    FILE *health = NULL;
    if (argc != 6) {
        fprintf(stderr, "usage: %s BPF_OBJECT TARGET_CGROUP_ID RAW_JSONL HEALTH_JSON READY_FILE\n", argv[0]);
        return 2;
    }
    libbpf_set_print(libbpf_log);
    target = strtoull(argv[2], NULL, 10);
    context.raw = fopen(argv[3], "w");
    health = fopen(argv[4], "w");
    if (!context.raw || !health) { perror("open output"); goto cleanup; }
    started_wall = clock_ns(CLOCK_REALTIME); started_mono = clock_ns(CLOCK_MONOTONIC);
    object = bpf_object__open_file(argv[1], NULL);
    if (!object || libbpf_get_error(object)) {
        fprintf(stderr, "failed to open BPF object %s\n", argv[1]);
        object = NULL;
        goto cleanup;
    }
    if (bpf_object__load(object)) {
        fprintf(stderr, "failed to load BPF object %s\n", argv[1]);
        goto cleanup;
    }
    target_map = bpf_object__find_map_fd_by_name(object, "target_cgroup_id");
    event_map = bpf_object__find_map_fd_by_name(object, "events");
    reserve_map = bpf_object__find_map_fd_by_name(object, "reserve_failures");
    update_map = bpf_object__find_map_fd_by_name(object, "map_update_failures");
    copy_map = bpf_object__find_map_fd_by_name(object, "path_copy_failures");
    truncation_map = bpf_object__find_map_fd_by_name(object, "path_truncations");
    if (target_map < 0 || event_map < 0 || reserve_map < 0 || update_map < 0 || copy_map < 0 || truncation_map < 0) goto cleanup;
    if (bpf_map_update_elem(target_map, &key, &target, BPF_ANY)) goto cleanup;
    bpf_object__for_each_program(program, object) {
        struct bpf_link *link;
        if (link_count >= MAX_LINKS) goto cleanup;
        link = bpf_program__attach(program);
        if (!link || libbpf_get_error(link)) {
            fprintf(stderr, "failed to attach BPF program %s\n", bpf_program__name(program));
            goto cleanup;
        }
        links[link_count++] = link;
    }
    ring = ring_buffer__new(event_map, handle_event, &context, NULL);
    if (!ring) goto cleanup;
    signal(SIGINT, stop_handler); signal(SIGTERM, stop_handler);
    { FILE *ready = fopen(argv[5], "w"); if (!ready) goto cleanup;
      fprintf(ready, "{\"ready\":true,\"scope\":\"cgroup_id\",\"cgroup_id\":%llu}\n", (unsigned long long)target);
      fclose(ready); }
    while (!stop_requested) { int polled = ring_buffer__poll(ring, 100); if (polled < 0 && polled != -4) goto cleanup; }
    result = 0;
cleanup:
    stopped_wall = clock_ns(CLOCK_REALTIME); stopped_mono = clock_ns(CLOCK_MONOTONIC);
    if (health) {
        fprintf(health, "{\"source\":\"ebpf_lifecycle\",\"collector_started_realtime_ns\":%llu,"
            "\"collector_started_monotonic_ns\":%llu,\"collector_stopped_realtime_ns\":%llu,"
            "\"collector_stopped_monotonic_ns\":%llu,\"events_emitted\":%llu,"
            "\"drop_count\":%llu,\"ring_reserve_failures\":%llu,\"map_update_failures\":%llu,"
            "\"path_copy_failures\":%llu,\"recovered_path_copy_failures\":%llu,"
            "\"unresolved_path_failures\":%llu,\"path_truncations\":%llu,"
            "\"overflow_count\":0,\"queue_high_water_mark\":0}\n",
            (unsigned long long)started_wall, (unsigned long long)started_mono,
            (unsigned long long)stopped_wall, (unsigned long long)stopped_mono,
            (unsigned long long)context.events,
            (unsigned long long)per_cpu_counter(reserve_map), (unsigned long long)per_cpu_counter(reserve_map),
            (unsigned long long)per_cpu_counter(update_map),
            (unsigned long long)per_cpu_counter(copy_map),
            (unsigned long long)context.recovered_path_copy_failures,
            (unsigned long long)context.unresolved_path_failures,
            (unsigned long long)per_cpu_counter(truncation_map));
        fclose(health);
    }
    ring_buffer__free(ring);
    while (link_count > 0) bpf_link__destroy(links[--link_count]);
    bpf_object__close(object);
    if (context.raw) fclose(context.raw);
    return result;
}
