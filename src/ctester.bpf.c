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

// LICENSE DUAL BSD & GPL
char __license [] SEC("license") = "Dual BSD/GPL";

static __always_inline process_t* get_process_by_pid(u32 pid)
{
    process_t* p = NULL;
    p = bpf_map_lookup_elem(&process_map,&pid);
    return p;
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
int BPF_PROG(do_open){

    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up the fs_wrap_stats using the current ID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);
    
    // Don't monitoring open syscall
    if (!fs_wrap || fs_wrap->monitor.monitoring_open == false)
        return -1;
    
    struct syscall_enter_open_args* args = (struct syscall_enter_open_args*)ctx;
    fs_wrap->open.last_params.flags = args->flags;
    fs_wrap->open.last_params.pathname = (const char*)args->filename_ptr;
    fs_wrap->open.last_params.mode = args->mode;
    
    lock_xadd(&fs_wrap->open.called,1);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int BPF_PROG(do_open_exit){
    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up the fs_wrap_stats using the current ID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);
    
    // Don't monitoring open syscall
    if (!fs_wrap || fs_wrap->monitor.monitoring_open == false)
        return -1;
    
    struct syscall_exit_open_args* args = (struct syscall_exit_open_args*)ctx;
    fs_wrap->open.last_return = args->ret;

    return 0;
}
 
SEC("tracepoint/syscalls/sys_enter_close")
int BPF_PROG(do_close){

    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up the fs_wrap_stats using current PID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);
    
    if(!fs_wrap || fs_wrap->monitor.monitoring_close == false)
        return -1;
    
    struct syscall_enter_close_args* args = (struct syscall_enter_close_args*)ctx;

    fs_wrap->close.last_params.fd = args->fd;

    lock_xadd(&fs_wrap->close.called,1);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int BPF_PROG(do_close_exit){
        //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up the fs_wrap_stats using the current ID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);
    
    // Don't monitoring open syscall
    if (!fs_wrap || fs_wrap->monitor.monitoring_close == false)
        return -1;

    struct syscall_exit_close_args* args = (struct syscall_exit_close_args*)ctx;

    fs_wrap->close.last_return = args->ret;

    return 0;
}


SEC("tracepoint/syscalls/sys_enter_creat")
int BPF_PROG(do_creat){

    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up fs_wrap_stats using current PID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);

    // Monitoring creat syscall desable
    if(!fs_wrap || fs_wrap->monitor.monitoring_creat == false)
        return -1;

    struct syscall_enter_creat_args* args = (struct syscall_enter_creat_args*)ctx;

    fs_wrap->creat.last_params.pathname = (const char*)args->filename_ptr;
    fs_wrap->creat.last_params.mode = args->mode;

    lock_xadd(&fs_wrap->creat.called,1);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_creat")
int BPF_PROG(do_creat_exit){

    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
        
    // Look up fs_wrap_stats using current PID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);

    // Monitoring creat syscall desable
    if(!fs_wrap || fs_wrap->monitor.monitoring_creat == false)
        return -1;

    struct syscall_exit_creat_args* args = (struct syscall_exit_creat_args*)ctx;

    fs_wrap->creat.last_return = args->ret;

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int BPF_PROG(do_read){

    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
        
    // Look up fs_wrap_stats using current PID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);

    // Monitoring read syscall desable
    if(!fs_wrap || fs_wrap->monitor.monitoring_read == false)
        return -1;
    
    struct syscall_enter_read_args* args = (struct syscall_enter_read_args*)ctx;

    fs_wrap->read.last_params.buf = (const char*)args->buf;
    fs_wrap->read.last_params.count = args->count;
    fs_wrap->read.last_params.fd = args->fd;
     
    lock_xadd(&fs_wrap->read.called,1);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int BPF_PROG(do_read_exit){
    
    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up fs_wrap_stats using current PID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);

    // Monitoring read syscall desable
    if(!fs_wrap || fs_wrap->monitor.monitoring_read == false)
        return -1;

    struct syscall_exit_read_args* args = (struct syscall_exit_read_args*)ctx;

    fs_wrap->read.last_return = args->ret;

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int BPF_PROG(do_write){

    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up fs_wrap_stats using current PID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);

    // Monitoring write syscall desable
    if(!fs_wrap || fs_wrap->monitor.monitoring_write == false)
        return -1;

    struct syscall_enter_write_args* args = (struct syscall_enter_write_args*)ctx;

    fs_wrap->write.last_params.buf = (const char*)args->buf;
    fs_wrap->write.last_params.count = args->count;
    fs_wrap->write.last_params.fd = args->fd;

    lock_xadd(&fs_wrap->write.called,1);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int BPF_PROG(do_write_exit){
    
    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up fs_wrap_stats using current PID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);

    // Monitoring write syscall desable
    if(!fs_wrap || fs_wrap->monitor.monitoring_write == false)
        return -1;
    
    struct syscall_exit_write_args* args = (struct syscall_exit_write_args*)ctx;

    fs_wrap->write.last_return = args->ret;

    return 0;
}


SEC("tracepoint/syscalls/sys_enter_newstat")
int BPF_PROG(do_newstat){

    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up fs_wrap_stats using current PID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);

    // Monitoring stat syscall desable
    if(!fs_wrap || fs_wrap->monitor.monitoring_stat == false)
        return -1;
    
    struct syscall_enter_stat_args* args = (struct syscall_enter_stat_args*)ctx;

    fs_wrap->stat.last_params.buf = (struct stat*)args->statbuf;
    fs_wrap->stat.last_params.path = (const char*)args->filename_ptr;

    lock_xadd(&fs_wrap->stat.called,1);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_newstat")
int BPF_PROG(do_newstat_exit){

    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up fs_wrap_stats using current PID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);

    // Monitoring stat syscall desable
    if(!fs_wrap || fs_wrap->monitor.monitoring_stat == false)
        return -1;

    struct syscall_exit_stat_args* args = (struct syscall_exit_stat_args*)ctx;

    fs_wrap->stat.last_return = args->ret;

    return 0;   
}

SEC("tracepoint/syscalls/sys_enter_newfstat")
int BPF_PROG(do_fstatfs){

    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up fs_wrap_stats using current PID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);

    // Monitoring fstat syscall desable
    if(!fs_wrap || fs_wrap->monitor.monitoring_fstat == false)
        return -1;

    struct syscall_enter_fstat_args* args = (struct syscall_enter_fstat_args*)ctx;

    fs_wrap->fstat.last_params.fd = args->fd;
    fs_wrap->fstat.last_params.buf = (struct stat*)args->statbuf;

    lock_xadd(&fs_wrap->fstat.called,1);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_newfstat")
int BPF_PROG(do_exit_fstatfs){

    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up fs_wrap_stats using current PID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);

    // Monitoring fstat syscall desable
    if(!fs_wrap || fs_wrap->monitor.monitoring_fstat == false)
        return -1;

    struct syscall_exit_fstat_args* args = (struct syscall_exit_fstat_args*)ctx;

    fs_wrap->fstat.last_return = args->ret;

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lseek")
int BPF_PROG(do_lseek){

    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up fs_wrap_stats using current PID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);

    // Monitoring lseek syscall desable
    if(!fs_wrap || fs_wrap->monitor.monitoring_lseek == false)
        return -1;
    
    struct syscall_enter_lseek_args* args = (struct syscall_enter_lseek_args*)ctx;

    fs_wrap->lseek.last_params.fd = args->fd;
    fs_wrap->lseek.last_params.offset = args->offset;
    fs_wrap->lseek.last_params.whence = args->whence;

    lock_xadd(&fs_wrap->lseek.called,1);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lseek")
int BPF_PROG(do_exit_lseek){

    //struct pt_regs* regs = (struct pt_regs*)ctx;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    process_t* process = get_process_by_pid(pid);
    
    // Untracked
    if (!process || (process->monitoring == false)){
        return -1;
    }
    
    // Look up fs_wrap_stats using current PID
    fs_wrap_stats_t* fs_wrap = get__fs_wrap_stats__by_host_pid(pid);

    // Monitoring lseek syscall desable
    if(!fs_wrap || fs_wrap->monitor.monitoring_lseek == false)
        return -1;

    struct syscall_exit_lseek_args* args = (struct syscall_exit_lseek_args*)ctx;

    fs_wrap->lseek.last_return = args->ret;

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
