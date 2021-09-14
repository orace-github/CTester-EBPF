#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ctester.h"

char LICENSE[] SEC("license") = "GPL";


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
  bool monitored;
  __u32 prog_pid;
  bool getpid;
  bool monitoring_open;
  bool monitoring_creat;
  bool monitoring_close;
  bool monitoring_read;
  bool monitoring_write;
  bool monitoring_stat;
  bool monitoring_fstat;
  bool monitoring_lseek;
  bool monitoring_free;
  bool monitoring_malloc;
  bool monitoring_calloc;
  bool monitoring_realloc;
  bool monitoring_sleep;
  bool start_student_code;
  bool end_student_code;
}ctester_cfg = {};


SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx){
    struct event *e;
    // Are we monitoring sysclose?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_open)
         return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
       
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return -1;
    u32 uid = (u32)bpf_get_current_uid_gid();
    e->type = SYS_ENTER_OPEN;
    e->uid = uid;
    e->pid = pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit* ctx){
    struct event *e;
    // Are we monitoring sysclose?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_open)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
       
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return -1;
    u32 uid = (u32)bpf_get_current_uid_gid();
    e->type = SYS_EXIT_OPEN;
    e->uid = uid;
    e->pid = pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter* ctx){
    struct event *e;
    
    // Are we monitoring sysclose?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_write)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
       
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
       return -1;
    u32 uid = (u32)bpf_get_current_uid_gid();
    e->type = SYS_ENTER_WRITE;
    e->uid = uid;
    e->pid = pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint__syscalls__sys_exit_write(struct trace_event_raw_sys_exit* ctx){
    struct event *e;
    
    // Are we monitoring sysclose?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_write)
       return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
       return -1;
       
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
       return -1;
    u32 uid = (u32)bpf_get_current_uid_gid();
    e->type = SYS_EXIT_WRITE;
    e->uid = uid;
    e->pid = pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter* ctx){
    struct event *e;
    
    // Are we monitoring sysclose?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_close)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
       
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return -1;
    u32 uid = (u32)bpf_get_current_uid_gid();
    e->type = SYS_ENTER_CLOSE;
    e->uid = uid;
    e->pid = pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int tracepoint__syscalls__sys_exit_close(struct trace_event_raw_sys_exit* ctx){
    struct event *e;
    
    // Are we monitoring sysclose?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_close)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
       
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return -1;
    u32 uid = (u32)bpf_get_current_uid_gid();
    e->type = SYS_EXIT_CLOSE;
    e->uid = uid;
    e->pid = pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int tracepoint__syscalls__sys_enter_creat(struct trace_event_raw_sys_enter* ctx){
    struct event *e;
    // Are we monitoring syscreat?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_creat)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
       
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return -1;
    u32 uid = (u32)bpf_get_current_uid_gid();
    e->type = SYS_ENTER_CREAT;
    e->uid = uid;
    e->pid = pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_creat")
int tracepoint__syscalls__sys_exit_creat(struct trace_event_raw_sys_exit* ctx){
    struct event *e;
    // Are we monitoring syscreat?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_creat)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
       
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return -1;
    u32 uid = (u32)bpf_get_current_uid_gid();
    e->type = SYS_EXIT_CREAT;
    e->uid = uid;
    e->pid = pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter* ctx){
    struct event *e;
    // Are we monitoring sysread?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_read)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
       
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return -1;
    u32 uid = (u32)bpf_get_current_uid_gid();
    e->type = SYS_ENTER_READ;
    e->uid = uid;
    e->pid = pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint__syscalls__sys_exit_read(struct trace_event_raw_sys_exit* ctx){
    struct event *e;
    // Are we monitoring sysread?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_read)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
       
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return -1;
    u32 uid = (u32)bpf_get_current_uid_gid();
    e->type = SYS_EXIT_READ;
    e->uid = uid;
    e->pid = pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
