// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 06, 2020  William Findlay  Created this.

#ifndef MAP_DEFS_H
#define MAP_DEFS_H

#include "maps.h"
#include "structs.h"
#include "syscall_wrap.h"


/* Filesystem syscall statistics */
BPF_HASH(fs_syscall, unsigned long, fs_wrap_stats_t, MAX_FS_STATISTICS, 0, 0);
/* Active (containerized) processes */
BPF_HASH(process_map, unsigned long, process_t, MAX_PROCESSES, 0, 0);

#endif /* ifndef MAP_DEFS_H */
