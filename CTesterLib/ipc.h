// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2021  Orace KPAKPO
//
// Sep. 02, 2021  Orace KPAKPO  created this.

#ifndef __IPC_H__
#define __IPC_H__
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>

// syscall flags
#define MONITORING_OPEN   0x01
#define MONITORING_CREAT  0x02
#define MONITORING_CLOSE  0x04
#define MONITORING_READ   0x08
#define MONITORING_WRITE  0x0f
#define MONITORING_STAT   0x10
#define MONITORING_FSTAT  0x20
#define MONITORING_LSEEK  0x40

// sysV msg type
enum{
    sys_enable_sandbox = 1,
    sys_disable_sandbox,
    sys_creat,
    sys_read,
    sys_write,
    sys_close,
    sys_lseek,
    sys_fstat,
    sys_open
};

#define MSG_MONITORING_OPEN   0x01
#define MSG_MONITORING_CREAT  0x02
#define MSG_MONITORING_CLOSE  0x04
#define MSG_MONITORING_READ   0x08
#define MSG_MONITORING_WRITE  0x0f
#define MSG_MONITORING_STAT   0x10
#define MSG_MONITORING_FSTAT  0x20
#define MSG_MONITORING_LSEEK  0x40
#define MSG_MONITORING_PID    0x80
#define MSG_UNMONITORING_PID  0xf0
#define MSG_ACK               0xff

#define CTESTER_SHM_SIZE 0x1000 // 4K
#define CTESTER_SHM_KEY 0x10	// 32
#define CTESTER_SHM_PERM 0666	
#define CTESTER_MSG_KEY 0x20  // 64
#define CTESTER_ACK_KEY 0x40  // 64
#define CTESTER_MSG_PERM  0666

struct msgbuf{
    long mtype;
    char mtext[24];
};

int receivemsg(int qid, long msgtype, struct msgbuf* buf);
int sndack(int ackqid, long msgtype);

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
} fs_wrap_stats_t;

// basic process structure 
typedef struct{
    unsigned long pid;
    unsigned long gid;
} process_t;

typedef struct{
   unsigned int count; // offset in data memory 
   char data[]; // raw buffer
} shm_metadata;

typedef struct {
    shm_metadata* shm; // shared memory
    long msgid; // msg queue id
    long ackqid; // ackq id
    fs_wrap_stats_t fs; // process field
    unsigned int monitor_sys_enable_sandbox:1;
    unsigned int monitor_sys_disable_sandbox:1;
    unsigned int monitor_sys_creat:1;
    struct {
        unsigned int pid : 1;
        unsigned int open : 1;
        unsigned int creat : 1;
        unsigned int close : 1;
        unsigned int read : 1;
        unsigned int write : 1;
        unsigned int stat : 1;
        unsigned int fstat : 1;
        unsigned int lseek : 1;
        unsigned int unused : 7;
    }monitored;
    void* m_map; // memory address
    void* ctx; // for CTester context purpose
} process_metadata;	

#endif //__IPC_H__
