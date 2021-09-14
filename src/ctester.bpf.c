// SPDX-License-Identifier: GPL-2.0-or-later
//
// CTester - syscall statistics with EBPF
// Copyright (C) 2021  Orace KPAKPO
// Sep, 01 2021 Orace KPAKPO  Created this.

#include "vmlinux.h"
#include "../CTesterLib/structs.h"
#include "../CTesterLib/maps_defs.h"
#include "../CTesterLib/allocator.h"
#include "../CTesterLib/syscall_args.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "ctester.h"

// LICENSE DUAL BSD & GPL
char __license [] SEC("license") = "Dual BSD/GPL";

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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline process_t* get_process_by_pid(u32 pid){
    return bpf_map_lookup_elem(&process_map,&pid);
   
}

static __always_inline fs_wrap_stats_t* get__fs_wrap_stats__by_host_pid(u32 pid)
{
    fs_wrap_stats_t* fs = NULL;
    fs = bpf_map_lookup_elem(&fs_syscall,&pid);
    return fs;
}

static __always_inline process_t* add_process(process_t* p)
{
    process_t* process = new_process_t();
    if(!process){
        // TODO : log that an error occurs
        return NULL;
    }
    process->gid = p->gid;
    process->pid = p->pid;
    process->monitoring = p->monitoring;

    fs_wrap_stats_t* wrap = new_fs_wrap_stats_t();
    if(!wrap){
        // TODO : log that an error occurs
        return NULL;
    }
    // push process into map
    bpf_map_update_elem(&process_map,&process->pid,process,BPF_NOEXIST);

    // push fs_wrap into map
    bpf_map_update_elem(&fs_syscall,&process->pid,wrap,BPF_NOEXIST);

    return bpf_map_lookup_elem(&process_map,&process->pid);
}

static __always_inline void monitoring_process_syscalls(process_t* p, u32 sys_flags){
    // set process monitoring attribute to true
    p->monitoring = true;

    // lookup syscall wrap from map
    fs_wrap_stats_t* wrap = bpf_map_lookup_elem(&fs_syscall,&p->pid);
    if(!wrap){
        // TODO: log that an error occurs
        return;
    }

    // set flags
    wrap->monitor.monitoring_close = (sys_flags & MONITORING_CLOSE) ? true : false;
    wrap->monitor.monitoring_creat = (sys_flags & MONITORING_CREAT) ? true : false;
    wrap->monitor.monitoring_open = (sys_flags & MONITORING_OPEN) ? true : false;
    wrap->monitor.monitoring_read = (sys_flags & MONITORING_READ) ? true : false;
    wrap->monitor.monitoring_write = (sys_flags & MONITORING_WRITE) ? true : false;
    wrap->monitor.monitoring_stat = (sys_flags & MONITORING_STAT) ? true : false;
    wrap->monitor.monitoring_fstat = (sys_flags & MONITORING_FSTAT) ? true : false;
    wrap->monitor.monitoring_lseek = (sys_flags & MONITORING_LSEEK) ? true : false;    
}

/* tracepoint syscall hooks */

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
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter* ctx)
{
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
int tracepoint__syscalls__sys_exit_write(struct trace_event_raw_sys_exit* ctx)
{
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
/* ========================================================================= *
 * Uprobe Commands                                                           *
 * ========================================================================= */

/* BPF program endpoint in CTester lib helpers. */

SEC("uprobe/ctester_add_process")
int BPF_KPROBE(ctester_add_process, process_t* p, unsigned int fs_flags, long* ret_p){

    long ret = -1;
    if(!p)
        goto out;

    process_t* pp = add_process(p);
    // create process context in map
    if(!pp)
        goto out;
    // monitoring fs syscalls
    monitoring_process_syscalls(pp,fs_flags);
    ret = 0;
out:
    if(ret_p)
        bpf_probe_write_user(ret_p, &ret, sizeof(ret));

    return 0;
}

SEC("uprobe/ctester_rm_process")
int BPF_KPROBE(ctester_rm_process, process_t* p, fs_wrap_stats_t* fs, long* ret_p){
    // TODO
    int ret = -1;
    if(!p || !fs)
        goto out;
    // delete process from map
    bpf_map_delete_elem(&process_map,&p->pid);
    // push statistics data to user space
    fs_wrap_stats_t* fsw = get__fs_wrap_stats__by_host_pid(p->pid);
    bpf_probe_write_user(fs,fsw,sizeof(fs_wrap_stats_t));
    // delete fs_wrap_statistics from map
    bpf_map_delete_elem(&fs_syscall,&p->pid);
    ret = 0;
out:
    if(ret_p)
        bpf_probe_write_user(ret_p, &ret, sizeof(ret));

    return 0;
}
