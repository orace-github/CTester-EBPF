// SPDX-License-Identifier: GPL-2.0-or-later
//
// CTester - syscall statistics with EBPF
// Copyright (C) 2021  Orace KPAKPO
// Sep, 06 2021 Orace KPAKPO  Created this.

#ifndef __SYSCALL_ARGS_H__
#define __SYSCALL_ARGS_H__

struct syscall_enter_open_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long filename_ptr;
    unsigned long long flags;
    unsigned long long mode;
};

struct syscall_exit_open_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;   
};

struct syscall_enter_creat_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long filename_ptr;
    unsigned long long mode;
};

struct syscall_exit_creat_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;
};

struct syscall_enter_close_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long fd;   
};

struct syscall_exit_close_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;
};

struct syscall_enter_read_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long fd;
    unsigned long long buf;
    unsigned long long count;   
};

struct syscall_exit_read_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;
};

struct syscall_enter_write_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long fd;
    unsigned long long buf;
    unsigned long long count;
};

struct syscall_exit_write_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;   
};

struct syscall_enter_stat_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long filename_ptr;
    unsigned long long statbuf;
};

struct  syscall_exit_stat_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;
};

struct syscall_enter_fstat_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long fd;
    unsigned long long statbuf;
};

struct syscall_exit_fstat_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;
};

struct syscall_enter_lseek_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long fd;
    unsigned long long offset;
    unsigned long long whence;
};

struct syscall_exit_lseek_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;
};

#define MONITORING_LSEEK  0x40

#endif //__SYSCALL_ARGS_H__