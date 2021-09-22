#ifndef __CTESTER_H
#define __CTESTER_H
#include "../CTesterLib/syscall_args.h"

enum {
  SYS_ENTER_OPEN,
  SYS_ENTER_EXEC,
  SYS_ENTER_WRITE,
  SYS_ENTER_CLOSE,
  SYS_ENTER_CREAT,
  SYS_ENTER_READ,
  SYS_ENTER_STAT,
  SYS_ENTER_FSTAT,
  SYS_ENTER_LSEEK,
  SYS_EXIT_OPEN,
  SYS_EXIT_EXEC,
  SYS_EXIT_WRITE,
  SYS_EXIT_CLOSE,
  SYS_EXIT_CREAT,
  SYS_EXIT_READ,
  SYS_EXIT_STAT,
  SYS_EXIT_FSTAT,
  SYS_EXIT_LSEEK,
};

struct event {
  int type;
  __u32 uid;
  __u32 pid;
  union{
    struct syscall_enter_open_args enter_open_args;
    struct syscall_enter_write_args enter_write_args;
    struct syscall_enter_close_args enter_close_args;
    struct syscall_enter_creat_args enter_creat_args;
    struct syscall_enter_read_args enter_read_args;
    struct syscall_enter_stat_args enter_stat_args;
    struct syscall_enter_fstat_args enter_fstat_args;
    struct syscall_enter_lseek_args enter_lseek_args;
    struct syscall_exit_open_args exit_open_args;
    struct syscall_exit_write_args exit_write_args;
    struct syscall_exit_close_args exit_close_args;
    struct syscall_exit_creat_args exit_creat_args;
    struct syscall_exit_read_args exit_read_args;
    struct syscall_exit_stat_args exit_stat_args;
    struct syscall_exit_fstat_args exit_fstat_args;
    struct syscall_exit_lseek_args exit_lseek_args;
  }args;
};


#endif /* __CTESTER_H */