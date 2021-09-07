// SPDX-License-Identifier: GPL-2.0-or-later
//
// CTester - syscall statistics with EBPF
// Copyright (C) 2021  Orace KPAKPO
// Sep, 01 2021 Orace KPAKPO  Created this.

#ifndef __STRUCTS_H__
#define __STRUCTS_H__
#include "user_types.h"
#include "../src/vmlinux.h"
// basic structure for process
/* 
 * 
 * @pid: current process pid
 * @gid current process gid
 * @monitoring: does syscall monitoring is set ?
 * 
 */
typedef struct{
    unsigned long pid;
    unsigned long gid;
    bool monitoring;    
}process_t __attribute__((__aligned__(8)));
#endif //__STRUCTS_H__