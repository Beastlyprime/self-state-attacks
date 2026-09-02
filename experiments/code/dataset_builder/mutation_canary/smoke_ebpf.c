#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define PREFIX_BYTES 16384
#define MAX_LINKS 32
#define KIND_WRITE 1
#define KIND_READ 2
#define KIND_RENAME 3
#define KIND_UNLINK 4
#define KIND_CHMOD 5

struct event {
    uint64_t kernel_monotonic_ns;
    uint64_t requested_count;
    int64_t actual_count;
    uint32_t pid;
    uint32_t tid;
    int32_t fd;
    uint32_t kind;
    uint32_t captured_bytes;
    int32_t capture_error;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    unsigned char data[PREFIX_BYTES];
};

struct collector_context { FILE *raw; uint64_t events; };
static volatile sig_atomic_t stop_requested;
static uint64_t clock_ns(clockid_t id) { struct timespec v; if (clock_gettime(id, &v)) return 0; return (uint64_t)v.tv_sec * 1000000000ULL + (uint64_t)v.tv_nsec; }
static void stop_handler(int signo) { (void)signo; stop_requested = 1; }
static void print_hex(FILE *output, const unsigned char *data, uint32_t length) { static const char d[]="0123456789abcdef"; for (uint32_t i=0;i<length;i++){ fputc(d[data[i]>>4], output); fputc(d[data[i]&15], output);} }
static const char *kind_name(uint32_t kind) { switch (kind) { case KIND_WRITE: return "write"; case KIND_READ: return "read"; case KIND_RENAME: return "rename"; case KIND_UNLINK: return "unlink"; case KIND_CHMOD: return "chmod"; default: return "unknown"; } }
static int handle_event(void *opaque, void *data, size_t size) {
    struct collector_context *ctx = opaque;
    const struct event *event = data;
    uint32_t captured;
    uint64_t realtime = clock_ns(CLOCK_REALTIME);
    uint64_t monotonic = clock_ns(CLOCK_MONOTONIC);
    if (size < sizeof(*event)) return 0;
    captured = event->captured_bytes;
    if (captured > PREFIX_BYTES) captured = PREFIX_BYTES;
    if (event->kind == KIND_READ || event->kind == KIND_WRITE) {
        fprintf(ctx->raw,
            "{\"record_type\":\"syscall_io\",\"source\":\"ebpf\","
            "\"timestamp_realtime_ns\":%llu,\"timestamp_monotonic_ns\":%llu,"
            "\"kernel_monotonic_ns\":%llu,\"kind\":\"%s\","
            "\"pid\":%u,\"tid\":%u,\"fd\":%d,"
            "\"requested_count\":%llu,\"actual_count\":%lld,"
            "\"buffer_prefix_capacity_bytes\":%d,"
            "\"buffer_prefix_captured_bytes\":%u,\"capture_error\":%d,"
            "\"buffer_prefix_hex\":\"",
            (unsigned long long)realtime, (unsigned long long)monotonic,
            (unsigned long long)event->kernel_monotonic_ns, kind_name(event->kind),
            event->pid, event->tid, event->fd,
            (unsigned long long)event->requested_count, (long long)event->actual_count,
            PREFIX_BYTES, captured, event->capture_error);
        print_hex(ctx->raw, event->data, captured);
        fputs("\"}\n", ctx->raw);
    } else {
        fprintf(ctx->raw,
            "{\"record_type\":\"syscall_mutation\",\"source\":\"ebpf\","
            "\"timestamp_realtime_ns\":%llu,\"timestamp_monotonic_ns\":%llu,"
            "\"kernel_monotonic_ns\":%llu,\"kind\":\"%s\","
            "\"pid\":%u,\"tid\":%u,\"actual_count\":%lld,"
            "\"arg0\":%llu,\"arg1\":%llu,\"arg2\":%llu,\"arg3\":%llu}\n",
            (unsigned long long)realtime, (unsigned long long)monotonic,
            (unsigned long long)event->kernel_monotonic_ns, kind_name(event->kind),
            event->pid, event->tid, (long long)event->actual_count,
            (unsigned long long)event->arg0, (unsigned long long)event->arg1,
            (unsigned long long)event->arg2, (unsigned long long)event->arg3);
    }
    fflush(ctx->raw);
    ctx->events++;
    return 0;
}
static uint64_t per_cpu_counter(int fd) { uint32_t key=0; int cpus=libbpf_num_possible_cpus(); uint64_t total=0,*values; if(fd<0||cpus<=0) return 0; values=calloc((size_t)cpus,sizeof(*values)); if(!values) return 0; if(bpf_map_lookup_elem(fd,&key,values)==0) for(int i=0;i<cpus;i++) total+=values[i]; free(values); return total; }
int main(int argc, char **argv) {
    struct bpf_object *object=NULL; struct bpf_program *program; struct bpf_link *links[MAX_LINKS]={}; struct ring_buffer *ring=NULL; struct collector_context context={}; uint64_t started_realtime,started_monotonic,stopped_realtime,stopped_monotonic,reserve_drops,capture_drops; long queue_high_water=0; uint32_t key=0,target; int target_map=-1,event_map=-1,reserve_map=-1,capture_map=-1,link_count=0,result=1; FILE *health=NULL;
    if(argc!=6){ fprintf(stderr,"usage: %s BPF_OBJECT TARGET_PID RAW_JSONL HEALTH_JSON READY_FILE\n",argv[0]); return 2; }
    target=(uint32_t)strtoul(argv[2],NULL,10); context.raw=fopen(argv[3],"w"); if(!context.raw){perror("open raw stream"); return 2;}
    started_realtime=clock_ns(CLOCK_REALTIME); started_monotonic=clock_ns(CLOCK_MONOTONIC);
    object=bpf_object__open_file(argv[1],NULL); if(libbpf_get_error(object)){object=NULL; fprintf(stderr,"cannot open BPF object\n"); goto cleanup;} if(bpf_object__load(object)){fprintf(stderr,"cannot load BPF object\n"); goto cleanup;}
    target_map=bpf_object__find_map_fd_by_name(object,"target_pid"); event_map=bpf_object__find_map_fd_by_name(object,"events"); reserve_map=bpf_object__find_map_fd_by_name(object,"reserve_failures"); capture_map=bpf_object__find_map_fd_by_name(object,"capture_failures"); if(target_map<0||event_map<0||reserve_map<0||capture_map<0){fprintf(stderr,"required BPF map is absent\n"); goto cleanup;}
    if(bpf_map_update_elem(target_map,&key,&target,BPF_ANY)){perror("set target pid"); goto cleanup;}
    bpf_object__for_each_program(program, object) { struct bpf_link *link; if(link_count>=MAX_LINKS){fprintf(stderr,"too many BPF programs\n"); goto cleanup;} link=bpf_program__attach(program); if(libbpf_get_error(link)){fprintf(stderr,"cannot attach BPF program\n"); goto cleanup;} links[link_count++]=link; }
    ring=ring_buffer__new(event_map,handle_event,&context,NULL); if(libbpf_get_error(ring)){ring=NULL; fprintf(stderr,"cannot create ring buffer\n"); goto cleanup;}
    signal(SIGINT,stop_handler); signal(SIGTERM,stop_handler); { FILE *ready=fopen(argv[5],"w"); if(!ready){perror("open ready file"); goto cleanup;} fprintf(ready,"%u\n",(unsigned int)getpid()); fclose(ready); }
    while(!stop_requested){ int polled=ring_buffer__poll(ring,100); if(polled==-EINTR) continue; if(polled<0){fprintf(stderr,"ring buffer poll failed: %d\n",polled); goto cleanup;} if(polled>queue_high_water) queue_high_water=polled; }
    result=0;
cleanup:
    if(ring) ring_buffer__free(ring); while(link_count>0) bpf_link__destroy(links[--link_count]); reserve_drops=object?per_cpu_counter(reserve_map):0; capture_drops=object?per_cpu_counter(capture_map):0; stopped_realtime=clock_ns(CLOCK_REALTIME); stopped_monotonic=clock_ns(CLOCK_MONOTONIC); health=fopen(argv[4],"w"); if(health){ fprintf(health,"{\"source\":\"ebpf\",\"collector_started_realtime_ns\":%llu,\"collector_started_monotonic_ns\":%llu,\"collector_stopped_realtime_ns\":%llu,\"collector_stopped_monotonic_ns\":%llu,\"events_emitted\":%llu,\"drop_count\":%llu,\"overflow_count\":%llu,\"queue_high_water_mark\":%ld,\"capture_failure_count\":%llu}\n",(unsigned long long)started_realtime,(unsigned long long)started_monotonic,(unsigned long long)stopped_realtime,(unsigned long long)stopped_monotonic,(unsigned long long)context.events,(unsigned long long)(reserve_drops+capture_drops),(unsigned long long)reserve_drops,queue_high_water,(unsigned long long)capture_drops); fclose(health);} if(object) bpf_object__close(object); if(context.raw) fclose(context.raw); return result;
}
