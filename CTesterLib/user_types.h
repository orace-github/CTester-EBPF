// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
// Copyrigth (C) 2021  Orace KPAKPO
//
// May 06, 2020  William Findlay  Created this.

#ifndef USER_TYPES_H
#define USER_TYPES_H

// TODO: This will no longer be necessary with task_local_storage in 5.11
#define MAX_PROCESSES 10240
#define MAX_FS_STATISTICS 10240

// builts-in atomic perform functions
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#define lock_xsub(ptr, val) ((void) __sync_fetch_and_sub(ptr, val))
#define lock_xor(ptr, val) ((void) __sync_fetch_and_or(ptr, val))
#define lock_xxor(ptr, val) ((void) __sync_fetch_and_xor(ptr, val))
#define lock_xand(ptr, val) ((void) __sync_fetch_and_and(ptr, val))
#define lock_xnand(ptr, val) ((void) __sync_fetch_and_nand(ptr, val))

#define __PACKED __attribute__((__packed__))

#endif /* ifndef USER_TYPES_H */

