#ifndef __CORE_H
#define __CORE_H

#define MONITORING(s,y)  skel->bss->ctester_cfg.monitoring_ ## s = y
#define SET_MONITORED_PID(pid)  skel->bss->ctester_cfg.prog_pid = pid
#define BEGIN_SANDBOX  skel->bss->ctester_cfg.monitored = true
#define END_SANDBOX  skel->bss->ctester_cfg.monitored = false

#endif /* __CORE_H */
