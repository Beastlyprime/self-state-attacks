#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PREFIX_BYTES 16384
#define MAX_LINKS 16

struct io_event {
    uint64_t kernel_monotonic_ns;
    uint64_t requested_count;
    int64_t actual_count;
    uint32_t pid;
    uint32_t tid;
    int32_t fd;
    uint32_t kind;
    uint32_t captured_bytes;
    int32_t capture_error;
    unsigned char data[PREFIX_BYTES];
};

struct collector_context {
    FILE *raw;
    uint64_t events;
};

static volatile sig_atomic_t stop_requested;

static uint64_t clock_ns(clockid_t clock_id)
{
    struct timespec value;
    if (clock_gettime(clock_id, &value) != 0)
        return 0;
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static void stop_handler(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static void print_hex(FILE *output, const unsigned char *data, uint32_t length)
{
    static const char digits[] = "0123456789abcdef";
    uint32_t index;
    for (index = 0; index < length; index++) {
        fputc(digits[data[index] >> 4], output);
        fputc(digits[data[index] & 15], output);
    }
}

static int handle_event(void *opaque, void *data, size_t size)
{
    struct collector_context *context = opaque;
    const struct io_event *event = data;
    uint32_t captured;
    uint64_t realtime = clock_ns(CLOCK_REALTIME);
    uint64_t monotonic = clock_ns(CLOCK_MONOTONIC);

    if (size < sizeof(*event))
        return 0;
    captured = event->captured_bytes;
    if (captured > PREFIX_BYTES)
        captured = PREFIX_BYTES;
    fprintf(context->raw,
        "{\"record_type\":\"syscall_io\",\"source\":\"ebpf\","
        "\"timestamp_realtime_ns\":%llu,\"timestamp_monotonic_ns\":%llu,"
        "\"kernel_monotonic_ns\":%llu,\"kind\":\"%s\","
        "\"pid\":%u,\"tid\":%u,\"fd\":%d,"
        "\"requested_count\":%llu,\"actual_count\":%lld,"
        "\"buffer_prefix_capacity_bytes\":%d,"
        "\"buffer_prefix_captured_bytes\":%u,\"capture_error\":%d,"
        "\"buffer_prefix_hex\":\"",
        (unsigned long long)realtime,
        (unsigned long long)monotonic,
        (unsigned long long)event->kernel_monotonic_ns,
        event->kind == 1 ? "write" : "read",
        event->pid,
        event->tid,
        event->fd,
        (unsigned long long)event->requested_count,
        (long long)event->actual_count,
        PREFIX_BYTES,
        captured,
        event->capture_error);
    print_hex(context->raw, event->data, captured);
    fputs("\"}\n", context->raw);
    fflush(context->raw);
    context->events++;
    return 0;
}

static uint64_t per_cpu_counter(int fd)
{
    uint32_t key = 0;
    int cpus = libbpf_num_possible_cpus();
    uint64_t total = 0;
    uint64_t *values;
    int index;
    if (fd < 0 || cpus <= 0)
        return 0;
    values = calloc((size_t)cpus, sizeof(*values));
    if (!values)
        return 0;
    if (bpf_map_lookup_elem(fd, &key, values) == 0)
        for (index = 0; index < cpus; index++)
            total += values[index];
    free(values);
    return total;
}

int main(int argc, char **argv)
{
    struct bpf_object *object = NULL;
    struct bpf_program *program;
    struct bpf_link *links[MAX_LINKS] = {};
    struct ring_buffer *ring = NULL;
    struct collector_context context = {};
    uint64_t started_realtime;
    uint64_t started_monotonic;
    uint64_t stopped_realtime;
    uint64_t stopped_monotonic;
    uint64_t reserve_drops;
    uint64_t capture_drops;
    long queue_high_water = 0;
    uint32_t key = 0;
    uint32_t target;
    int target_map = -1;
    int event_map = -1;
    int reserve_map = -1;
    int capture_map = -1;
    int link_count = 0;
    int result = 1;
    FILE *health = NULL;

    if (argc != 6) {
        fprintf(stderr, "usage: %s BPF_OBJECT TARGET_PID RAW_JSONL HEALTH_JSON READY_FILE\n", argv[0]);
        return 2;
    }
    target = (uint32_t)strtoul(argv[2], NULL, 10);
    context.raw = fopen(argv[3], "w");
    if (!context.raw) {
        perror("open raw stream");
        return 2;
    }
    started_realtime = clock_ns(CLOCK_REALTIME);
    started_monotonic = clock_ns(CLOCK_MONOTONIC);
    object = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(object)) {
        object = NULL;
        fprintf(stderr, "cannot open BPF object\n");
        goto cleanup;
    }
    if (bpf_object__load(object)) {
        fprintf(stderr, "cannot load BPF object\n");
        goto cleanup;
    }
    target_map = bpf_object__find_map_fd_by_name(object, "target_pid");
    event_map = bpf_object__find_map_fd_by_name(object, "events");
    reserve_map = bpf_object__find_map_fd_by_name(object, "reserve_failures");
    capture_map = bpf_object__find_map_fd_by_name(object, "capture_failures");
    if (target_map < 0 || event_map < 0 || reserve_map < 0 || capture_map < 0) {
        fprintf(stderr, "required BPF map is absent\n");
        goto cleanup;
    }
    if (bpf_map_update_elem(target_map, &key, &target, BPF_ANY)) {
        perror("set target pid");
        goto cleanup;
    }
    bpf_object__for_each_program(program, object) {
        struct bpf_link *link;
        if (link_count >= MAX_LINKS) {
            fprintf(stderr, "too many BPF programs\n");
            goto cleanup;
        }
        link = bpf_program__attach(program);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "cannot attach BPF program\n");
            goto cleanup;
        }
        links[link_count++] = link;
    }
    ring = ring_buffer__new(event_map, handle_event, &context, NULL);
    if (libbpf_get_error(ring)) {
        ring = NULL;
        fprintf(stderr, "cannot create ring buffer\n");
        goto cleanup;
    }
    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);
    {
        FILE *ready = fopen(argv[5], "w");
        if (!ready) {
            perror("open ready file");
            goto cleanup;
        }
        fprintf(ready, "%u\n", (unsigned int)getpid());
        fclose(ready);
    }
    while (!stop_requested) {
        int polled = ring_buffer__poll(ring, 100);
        if (polled == -EINTR)
            continue;
        if (polled < 0) {
            fprintf(stderr, "ring buffer poll failed: %d\n", polled);
            goto cleanup;
        }
        if (polled > queue_high_water)
            queue_high_water = polled;
    }
    result = 0;

cleanup:
    if (ring)
        ring_buffer__free(ring);
    while (link_count > 0)
        bpf_link__destroy(links[--link_count]);
    reserve_drops = object ? per_cpu_counter(reserve_map) : 0;
    capture_drops = object ? per_cpu_counter(capture_map) : 0;
    stopped_realtime = clock_ns(CLOCK_REALTIME);
    stopped_monotonic = clock_ns(CLOCK_MONOTONIC);
    health = fopen(argv[4], "w");
    if (health) {
        fprintf(health,
            "{\"source\":\"ebpf\","
            "\"collector_started_realtime_ns\":%llu,"
            "\"collector_started_monotonic_ns\":%llu,"
            "\"collector_stopped_realtime_ns\":%llu,"
            "\"collector_stopped_monotonic_ns\":%llu,"
            "\"events_emitted\":%llu,\"drop_count\":%llu,"
            "\"overflow_count\":%llu,\"queue_high_water_mark\":%ld,"
            "\"capture_failure_count\":%llu}\n",
            (unsigned long long)started_realtime,
            (unsigned long long)started_monotonic,
            (unsigned long long)stopped_realtime,
            (unsigned long long)stopped_monotonic,
            (unsigned long long)context.events,
            (unsigned long long)(reserve_drops + capture_drops),
            (unsigned long long)reserve_drops,
            queue_high_water,
            (unsigned long long)capture_drops);
        fclose(health);
    }
    if (object)
        bpf_object__close(object);
    if (context.raw)
        fclose(context.raw);
    return result;
}
