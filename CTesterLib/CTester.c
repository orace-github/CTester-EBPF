// SPDX-License-Identifier: GPL-2.0-or-later
//
// CTester - syscall statistics with EBPF
// Copyright (C) 2021  Orace KPAKPO
// Sep, 02 2021 Orace KPAKPO  Created this.

#include <stdio.h>
#include "CTester.h"

#define get_monitoring_state(p, s)  p->monitor_ ## s


// CTester shared memory helper
process_metadata* shm_malloc(shm_metadata* shm){
    // - check memory boundary
    if(((CTESTER_SHM_SIZE-(sizeof(shm_metadata)))/sizeof(process_metadata)) <= shm->count ){
        fprintf(stderr, "Not enough espace in the shared memory\n");
        return NULL;
    }
    fprintf(stderr, "%ld:%d\n",((CTESTER_SHM_SIZE-(sizeof(shm_metadata)))/sizeof(process_metadata)), shm->count );
    process_metadata* p = (process_metadata*)(shm->data);
    process_metadata* pp = &p[shm->count];
    shm->count++;
    return pp;
}

void shm_free(process_metadata* p){
    if(!p)
        return;
    // TODO
}

static int sndmsg(CTESTER_CTX ctx, int msgtype, bool b){
    struct msgbuf buf;
    int err;
    buf.mtype = (long)msgtype;
    if((msgtype == sys_enable_sandbox) || (msgtype == sys_disable_sandbox)){
        process_t pm;
        pm.gid = getgid();
        pm.pid = getpid();
        memcpy(buf.mtext,&pm,sizeof(buf.mtext));
        fprintf(stderr, "here haha\n");
    }else
        buf.mtext[0] = (char)b;
    process_metadata* p = (process_metadata*)ctx;
    err = msgsnd(p->msgid,&buf,sizeof(buf.mtext),0);
    if(err < 0){
      fprintf(stderr,  "Unable to send the message: %s:%ld: %ld:%ld\n", strerror(errno),p->msgid, sizeof(buf), buf.mtype );
      return err;
    }
    int nsleep = 0;
    switch(msgtype){
        case sys_enable_sandbox:
            while(!get_monitoring_state(p, sys_enable_sandbox)){
                if(nsleep++ > 10)
                    return -1;
                usleep(100000);
                fprintf(stderr,"Send_inner %d:%p msg\n", msgtype, p);
            }
            break;
        case sys_disable_sandbox:
            while(get_monitoring_state(p, sys_enable_sandbox)){
                if(nsleep++ > 10)
                    return -1;
                usleep(100000);
                fprintf(stderr,"Send_inner 2 %d:%p msg\n", msgtype, p);
            }
            break;
    }
    fprintf(stderr,"Send_outer 2 %d:%d:%d msg\n", msgtype, sys_enable_sandbox, sys_disable_sandbox );
    return 0;
}

int sndack(int ackqid, long msgtype){
    struct msgbuf buf;
    int err;
    long type = msgtype;
    buf.mtype = MSG_ACK;
    memcpy(&type, &buf.mtext[0], sizeof(long));
    err =  msgsnd(ackqid,&buf,sizeof(buf.mtext),0);
    fprintf(stderr,"Send ACK for %ld msg\n", msgtype);
    return err;
}

int receivemsg(int qid, long msgtype, struct msgbuf* buf){
    int err;
    err = msgrcv(qid,buf,sizeof(buf->mtext),msgtype,IPC_NOWAIT);
    if(err < 0){
        return -1;
    }
    return 0;
}


CTESTER_CTX CTESTER_INIT_CTX(void){
   // - get shared memory
   int shmID, id, id2;
   shmID = shmget(CTESTER_SHM_KEY,CTESTER_SHM_SIZE,CTESTER_SHM_PERM);
   if(shmID < 0){
      fprintf(stderr, "Unable to get SHM\n");				
      return NULL;
   }
   shm_metadata* shm = (shm_metadata*)shmat(shmID,NULL,0);	
   if(shm == (void*)-1){
      fprintf(stderr, "Unable to attach SHM (%d)\n", shmID);
      return NULL; 
   } 
   
   id = msgget(CTESTER_MSG_KEY,CTESTER_MSG_PERM);
   if(id < 0 ){
       fprintf(stderr, "Unable to get MSG\n");
       return NULL;
   }
   
   id2 = msgget(CTESTER_ACK_KEY,CTESTER_MSG_PERM);
   if(id2 < 0 ){
       fprintf(stderr, "Unable to get ACK MSG QUEUE\n");
       return NULL;
   }
   
   process_metadata* p = shm_malloc(shm);
   if(!p){
      fprintf(stderr, "Unable to allocate process_metadata in SHM\n");
      return NULL;
   }
   // clear all flags
   memset(&p->monitored,0,sizeof(p->monitored));
   p->shm = shm;
   p->msgid = id;
   p->ackqid = id2;
   p->ctx = (void*)p;	
   return p->ctx;
}

int CTESTER_ADD_PROCESS(CTESTER_CTX ctx){
    if(!ctx){ 
        fprintf(stderr, "Failed: Unitialized context\n");
        return -1;
    }
    return sndmsg(ctx,sys_enable_sandbox,true);
}

int CTESTER_REMOVE_PROCESS(CTESTER_CTX ctx){
    if(!ctx){ 
        fprintf(stderr, "Failed: to release context\n");
        return -1;
    }
    return sndmsg(ctx,sys_disable_sandbox,true);
}

int CTESTER_RELEASE_CTX(CTESTER_CTX ctx){
    if(!ctx) 
        return -1;
    // - get process pid gid
    //process_metadata* p = (process_metadata*)ctx;
    // TODO should release memory related to that context
    return CTESTER_REMOVE_PROCESS(ctx);  
      
}

void CTESTER_SET_MONITORING(CTESTER_CTX ctx, CTESTER_SYSCALL sys, bool b){
    if(!ctx) 
		return;
	// - get process pid gid
	process_metadata* p = (process_metadata*)ctx;
	
	if(sys == SYS_OPEN){
		sndmsg(ctx,sys_open,b);
	}
	else if(sys == SYS_CLOSE){
		sndmsg(ctx,sys_close,b);
	}
	else if(sys == SYS_CREAT){
		sndmsg(ctx,sys_creat,b);
		
	}
	else if(sys == SYS_FSTAT){
		sndmsg(ctx,sys_fstat,b);
	}
	else if(sys == SYS_LSEEK){
		sndmsg(ctx,sys_lseek,b);
	}
	else if(sys == SYS_READ){
		sndmsg(ctx,sys_read,b);
		
	}
	else if(sys == SYS_WRITE){
		sndmsg(ctx,sys_write,b);
	}
	else if(sys == SYS_STAT){
		sndmsg(ctx,MSG_MONITORING_STAT,b);
		while(!p->monitored.stat);
	}
}

void CTESTER_PRINT_STATISTICS(CTESTER_CTX ctx){
	if(!ctx)
		return;

	process_metadata* p = (process_metadata*)ctx;
	if(p->fs.close.called){
		fprintf(stdout,"sys_close called:(%d)\n",p->fs.close.called);
	}
	if(p->fs.creat.called){
		fprintf(stdout,"sys_creat called:(%d)\n",p->fs.creat.called);
	}
	if(p->fs.fstat.called){
		fprintf(stdout,"sys_fstat called:(%d)\n",p->fs.fstat.called);
	}
	if(p->fs.read.called){
		fprintf(stdout,"sys_read called:(%d)\n",p->fs.read.called);
	}
	if(p->fs.write.called){
		fprintf(stdout,"sys_write called:(%d)\n",p->fs.write.called);
	}
	if(p->fs.open.called){
		fprintf(stdout,"sys_open called:(%d)\n",p->fs.open.called);
	}
}