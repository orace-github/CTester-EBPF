// SPDX-License-Identifier: GPL-2.0-or-later
//
// CTester - syscall statistics with EBPF
// Copyright (C) 2021  Orace KPAKPO
// Sep, 02 2021 Orace KPAKPO  Created this.

#ifndef __CTESTER_LIB_H
#define __CTESTER_LIB_H
#include "ipc.h"

#define ARRAY_SZE(x) ((sizeof(x))/sizeof(x[0]))
#define OFFSET(type,field) (long)(&((type*)0)->field)
#define ENTRY(ptr,type,field) (type*)((char*)(ptr) - (char*)(&((type*)0)->field))

// CTester system call
typedef enum{
	SYS_OPEN,
	SYS_CREAT,
	SYS_CLOSE,
	SYS_READ,
	SYS_WRITE,
	SYS_STAT,
	SYS_FSTAT,
	SYS_LSEEK,
} CTESTER_SYSCALL;

// Abstract CTester sandbox context
typedef void* CTESTER_CTX; 

// CTester shared memory helpers

extern CTESTER_CTX CTESTER_INIT_CTX(void);

extern int CTESTER_ADD_PROCESS(CTESTER_CTX ctx);

extern int CTESTER_REMOVE_PROCESS(CTESTER_CTX ctx);

extern int CTESTER_RELEASE_CTX(CTESTER_CTX ctx);

extern void CTESTER_SET_MONITORING(CTESTER_CTX ctx, CTESTER_SYSCALL sys, bool b);


/* CTester sandbox */

#define CTESTER_SANDBOX_INIT()({	                  \
	int err;				          \
	CTESTER_CTX ctx = CTESTER_INIT_CTX();		  \
	if(!ctx){					  \
		perror("failed to init sandbox context"); \
		exit(-1);				  \
	}					          \
	ctx;						  \
}) 		

#define CTESTER_SANDBOX_ENTER(ctx)({	                  \
	int err;					  \
	err = CTESTER_ADD_PROCESS(ctx);	                  \
	if(err < 0){					  \
		perror("failed to enter sandbox");	  \
		CTESTER_RELEASE_CTX(ctx);		  \
		exit(-1);				  \
	}						  \
})

#define CTESTER_SANDBOX_EXIT(ctx) ({	                  \
	int err;					  \
	err = CTESTER_REMOVE_PROCESS(ctx);	          \
	if(err < 0){					  \
		perror("failed to exit sandbox");	  \
	}						  \
	CTESTER_RELEASE_CTX(ctx);			  \
})

#endif //__CTESTER_LIB_H
