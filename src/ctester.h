#ifndef __CTESTER_H
#define __CTESTER_H


enum {
  SYS_ENTER_OPEN,
  SYS_ENTER_EXEC,
  SYS_ENTER_WRITE,
  SYS_ENTER_CLOSE,
  SYS_ENTER_CREAT,
  SYS_ENTER_READ,
  SYS_EXIT_OPEN,
  SYS_EXIT_EXEC,
  SYS_EXIT_WRITE,
  SYS_EXIT_CLOSE,
  SYS_EXIT_CREAT,
  SYS_EXIT_READ
};

struct event {
  int type;
  __u32 uid;
  __u32 pid;
};


#endif /* __CTESTER_H */
