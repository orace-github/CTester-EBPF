// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2021  Orace KPAKPO
//
// Sep. 02, 2021  Orace KPAKPO  created this.

#ifndef __IPC_H__
#define __IPC_H__
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>

// syscall flags
#define MONITORING_OPEN   0x01
#define MONITORING_CREAT  0x02
#define MONITORING_CLOSE  0x04
#define MONITORING_READ   0x08
#define MONITORING_WRITE  0x0f
#define MONITORING_STAT   0x10
#define MONITORING_FSTAT  0x20
#define MONITORING_LSEEK  0x40

// basic structure to record the parameters of the last open call
struct params_open_t {
  char *pathname;
  int flags;
  mode_t mode;
}; 

// basic statistics for the utilisation of the open system call
struct stats_open_t {
  int called;  // number of times the open system call has been issued
  struct params_open_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last open call issued
};

struct params_creat_t {
  char *pathname;
  mode_t mode;
}; 

// basic statistics for the utilisation of the creat system call
struct stats_creat_t {
  int called;  // number of times the open system call has been issued
  struct params_creat_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last open call issued
};

struct params_close_t {
  int fd;
}; 

// basic statistics for the utilisation of the close system call
struct stats_close_t {
  int called;  // number of times the open system call has been issued
  struct params_close_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last open call issued
};

struct params_read_t {
  int fd;
  void *buf;
  ssize_t count;
}; 

// basic statistics for the utilisation of the read system call
struct stats_read_t {
  int called;  // number of times the read system call has been issued
  struct params_read_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last read call issued
};

struct params_write_t {
  int fd;
  void *buf;
  ssize_t count;
}; 

// basic statistics for the utilisation of the write system call
struct stats_write_t {
  int called;  // number of times the write system call has been issued
  struct params_read_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last read call issued
};

struct params_stat_t {
  char *path;
  struct stat *buf;
}; 

// basic statistics for the utilisation of the stat system call
struct stats_stat_t {
  int called;  // number of times the write system call has been issued
  struct params_stat_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last read call issued
  struct stat returned_stat; // last returned stat structure
};

struct params_fstat_t {
  int fd;
  struct stat *buf;
}; 

// basic statistics for the utilisation of the fstat system call
struct stats_fstat_t {
  int called;  // number of times the write system call has been issued
  struct params_fstat_t last_params; // parameters for the last call issued
  int last_return;   // return value of the last read call issued
  struct stat returned_stat; // last returned stat structure
};

struct params_lseek_t {
  int fd;
  off_t offset;
  int whence;
}; 

// basic statistics for the utilisation of the fstat system call
struct stats_lseek_t {
  int called;  // number of times the lseek system call has been issued
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
}fs_wrap_stats_t;

// basic process structure 
typedef struct{
    unsigned long pid;
    unsigned long gid;
    bool monitoring;    
} process_t;

#define CTESTER_SHM_SIZE 0x1000 // 4096 bytes
#define CTESTER_SHM_KEY 0x10	// 32
#define CTESTER_SHM_PERM 0666	

typedef struct{
	// shared memory info
	unsigned int shm_key;
	unsigned int shm_size;
	// buffer
	unsigned int offset; // offset in data memory 
	char data[]; // raw buffer
} shm_metadata;

typedef struct {
	// shared memory
	shm_metadata* shm;
	// process field
	process_t p;
	fs_wrap_stats_t fs;
	unsigned int fs_flags;
	// memory handling field
	unsigned int lmaped; // ctester lib side
	unsigned int cmaped; // ctester deamon side 
	void* m_map; // memory address
	void* ctx; // for CTester context purpose
} process_metadata;	// Do not modify this data

#endif //__IPC_H__