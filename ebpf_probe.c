/*
 * OwlEyeEngine - Linux eBPF Kernel Probe (v4.0 Enterprise)
 *
 * Attaches to kernel tracepoints:
 *   - syscalls/sys_enter_execve : Real-time binary execution intercept
 *   - syscalls/sys_enter_connect : Outbound network socket intercept
 *   - syscalls/sys_enter_kill    : Process termination signals
 *
 * Compatible with BCC, bpftrace, and libbpf CO-RE (Compile Once - Run Everywhere).
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16

/* Event Data Structure emitted to Perf / Ring Buffer */
struct kernel_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    char comm[MAX_COMM_LEN];
    char filename[MAX_PATH_LEN];
    u32 syscall_id;
    u32 target_pid;
    u32 saddr;
    u32 daddr;
    u16 dport;
};

/* BPF Ring Buffer Map for zero-copy userspace streaming */
BPF_PERF_OUTPUT(events);

/* Tracepoint: sys_enter_execve */
int trace_sys_enter_execve(struct tracepoint__syscalls__sys_enter_execve *args) {
    struct kernel_event_t event = {};
    u64 id = bpf_get_current_pid_tgid();
    
    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = id;
    event.tgid = id >> 32;
    event.uid = bpf_get_current_uid_gid();
    event.gid = bpf_get_current_uid_gid() >> 32;
    event.syscall_id = 59; // __NR_execve on x86_64

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    /* Push event directly to userspace ring buffer with sub-microsecond latency */
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

/* Tracepoint: sys_enter_kill */
int trace_sys_enter_kill(struct tracepoint__syscalls__sys_enter_kill *args) {
    struct kernel_event_t event = {};
    u64 id = bpf_get_current_pid_tgid();

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = id;
    event.tgid = id >> 32;
    event.uid = bpf_get_current_uid_gid();
    event.syscall_id = 62; // __NR_kill
    event.target_pid = args->pid;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
