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

#define CTESTER_SHM_SIZE 0x1000 // 4096 bytes
#define CTESTER_SHM_KEY 0x10	// 32
#define CTESTER_SHM_PERM 0666	
#define CTESTER_MSG_KEY 0x20  // 64
#define CTESTER_MSG_PERM  0666

struct msgbuf{
  long mtype;
  char mtext[24];
};

int sendmsg(int qid, long msgtype, bool b /* monitoring syscall false/true */);
int recvmsg(int qid, long msgtype, struct msgbuf* buf);

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
	// buffer
	unsigned int count; // offset in data memory 
	char data[]; // raw buffer
} shm_metadata;

typedef struct {
	// shared memory
	shm_metadata* shm;
	// msg
  long msgid;
  // process field
	fs_wrap_stats_t fs;
	// memory handling field
	//unsigned int lmaped; // ctester lib side
	//unsigned int cmaped; // ctester deamon side 
  struct {
    char pid : 1;
    char open : 1;
    char creat : 1;
    char close : 1;
    char read : 1;
    char write : 1;
    char stat : 1;
    char fstat : 1;
    char lseek : 1;
    char unused : 7;
  }monitored;
	void* m_map; // memory address
	void* ctx; // for CTester context purpose
} process_metadata;	// Do not modify this data

#endif //__IPC_H__