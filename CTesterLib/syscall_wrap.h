// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2021  Orace KPAKPO
//
// Aug 26, 2021  Orace KPAKPO  Created this.

#ifndef __SYSCALL_WRAP
#define __SYSCALL_WRAP
#include "user_types.h"
/* fs syscall */
#include "../src/vmlinux.h"

// syscall flags
#define MONITORING_OPEN   0x01
#define MONITORING_CREAT  0x02
#define MONITORING_CLOSE  0x04
#define MONITORING_READ   0x08
#define MONITORING_WRITE  0x0f
#define MONITORING_STAT   0x10
#define MONITORING_FSTAT  0x20
#define MONITORING_LSEEK  0x40

// open syscall arguments
struct params_open_t {
  const char* pathname;
  int flags;
  fmode_t mode;
}; 

// basic statistics for the utilisation of the open system call
struct stats_open_t {
  int called;  // number of times the open system call has been issued, and should be modify atomically
  struct params_open_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last open call issued
};

// creat syscall arguments
struct params_creat_t {
  const char *pathname;
  fmode_t mode;
}; 

// basic statistics for the utilisation of the creat system call
struct stats_creat_t {
  int called;  // number of times the open system call has been issued, and should be modify atomically
  struct params_creat_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last open call issued
};

// close syscall argument
struct params_close_t {
  int fd;
}; 

// basic statistics for the utilisation of the close system call
struct stats_close_t {
  int called;  // number of times the open system call has been issued, and should be modify atomically
  struct params_close_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last open call issued
};

// read syscall arguments
struct params_read_t {
  int fd;
  const char *buf;
  ssize_t count;
}; 

// basic statistics for the utilisation of the read system call
struct stats_read_t {
  int called;  // number of times the read system call has been issued, and should be modify atomically
  struct params_read_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last read call issued
};

// write syscall argument
struct params_write_t {
  int fd;
  const char *buf;
  ssize_t count;
}; 

// basic statistics for the utilisation of the write system call
struct stats_write_t {
  int called;  // number of times the write system call has been issued, and should be modify atomically
  struct params_read_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last read call issued
};

// stat syscall argument
struct params_stat_t {
  const char *path;
  struct stat *buf;
}; 

// basic statistics for the utilisation of the stat system call
struct stats_stat_t {
  int called;  // number of times the write system call has been issued, and should be modify atomically
  struct params_stat_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last read call issued
  struct stat returned_stat; // last returned stat structure
};

// fstat syscall argument
struct params_fstat_t {
  int fd;
  struct stat *buf;
}; 

// basic statistics for the utilisation of the fstat system call
struct stats_fstat_t {
  int called;  // number of times the write system call has been issued, and should be modify atomically
  struct params_fstat_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last read call issued
  struct stat returned_stat; // last returned stat structure
};

// lseek syscall arguments
struct params_lseek_t {
  int fd;
  off_t offset;
  int whence;
}; 

// basic statistics for the utilisation of the lseek system call
struct stats_lseek_t {
  int called;  // number of times the lseek system call has been issued, and should be modify atomically
  struct params_lseek_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last lseek call issued
};

// basic struct to monitoring fs system call
#define MONITORING(sys) bool monitoring_ ## sys
typedef struct{
    MONITORING(open);
    MONITORING(creat);
    MONITORING(close);
    MONITORING(read);
    MONITORING(write);
    MONITORING(stat);
    MONITORING(fstat);
    MONITORING(lseek);
}fs_monitoring_t;

// basic statistics for the utilisation of the (open|creat|read|write|close|stat|fstat|lseek) system calls
typedef struct{
    struct stats_open_t open;
    struct stats_creat_t creat;
    struct stats_close_t close;
    struct stats_read_t read;
    struct stats_write_t write;
    struct stats_stat_t stat;
    struct stats_fstat_t fstat;
    struct stats_lseek_t lseek;
    fs_monitoring_t monitor;
}fs_wrap_stats_t __attribute__((__aligned__(8)));

#endif //__SYSCALL_WRAP 