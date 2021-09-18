// SPDX-License-Identifier: GPL-2.0-or-later
//
// CTester - syscall statistics with EBPF
// Copyright (C) 2021  Orace KPAKPO
// Sep, 02 2021 Orace KPAKPO  Created this.

#include <stdio.h>
#include "CTester.h"

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

int sndmsg(int qid, long msgtype, bool b){
    struct msgbuf buf;
    int err;
    buf.mtype = msgtype;
    if(msgtype == MSG_MONITORING_PID || msgtype == MSG_UNMONITORING_PID){
        process_t p;
        p.gid = getgid();
        p.pid = getpid();
        memcpy(buf.mtext,&p,sizeof(buf.mtext));
    }else
        buf.mtext[0] = (char)b;
    err = msgsnd(qid,&buf,sizeof(buf.mtext),0);
    if(err)
      return err;
    fprintf(stderr,"Send %ld msg\n", msgtype);
    return 0;
}

int receivemsg(int qid, long msgtype, struct msgbuf* buf){
    int err;
    err = msgrcv(qid,buf,sizeof(buf->mtext),msgtype,IPC_NOWAIT);
    if(err < 0)
        return -1;
    return 0;
}


CTESTER_CTX CTESTER_INIT_CTX(void){
   // - get shared memory
   int shmID, id;
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
   process_metadata* p = shm_malloc(shm);
   if(!p){
      fprintf(stderr, "Unable to allocate process_metadata in SHM\n");
      return NULL;
   }
   // clear all flags
   memset(&p->monitored,0,sizeof(p->monitored));
   p->shm = shm;
   p->msgid = id;
   p->ctx = (void*)p;	
   return p->ctx;
}

int CTESTER_ADD_PROCESS(CTESTER_CTX ctx){
    if(!ctx){ 
        fprintf(stderr, "Failed: Unitialized context\n");
        return -1;
    }
    process_metadata* p = (process_metadata*)ctx;
    sndmsg(p->msgid,MSG_MONITORING_PID,true);
    fprintf(stderr, "process id (%d)\n", p->monitored.pid);
    while(!p->monitored.pid);
    fprintf(stderr, "process was added in the context\n");
    return 0;
}

int CTESTER_REMOVE_PROCESS(CTESTER_CTX ctx)
{
    if(!ctx) 
		return -1;
	// - get process pid gid
	process_metadata* p = (process_metadata*)ctx;
	sndmsg(p->msgid,MSG_UNMONITORING_PID,true);
	while(p->monitored.pid);
	return 0;
}

int CTESTER_RELEASE_CTX(CTESTER_CTX ctx)
{
    if(!ctx) 
		return -1;
	// - get process pid gid
	//process_metadata* p = (process_metadata*)ctx;
	CTESTER_REMOVE_PROCESS(ctx);
    
    return 0;
}

void CTESTER_SET_MONITORING(CTESTER_CTX ctx, CTESTER_SYSCALL sys, bool b)
{
    if(!ctx) 
		return;
	// - get process pid gid
	process_metadata* p = (process_metadata*)ctx;
	if(sys == SYS_OPEN){
		sndmsg(p->msgid,MSG_MONITORING_OPEN,b);
		while(!p->monitored.open);
	}
	else if(sys == SYS_CLOSE){
		sndmsg(p->msgid,MSG_MONITORING_CLOSE,b);
		while(!p->monitored.close);
	}
	else if(sys == SYS_CREAT){
		sndmsg(p->msgid,MSG_MONITORING_CREAT,b);
		while(!p->monitored.creat);
	}
	else if(sys == SYS_FSTAT){
		sndmsg(p->msgid,MSG_MONITORING_FSTAT,b);
		while(!p->monitored.fstat);
	}
	else if(sys == SYS_LSEEK){
		sndmsg(p->msgid,MSG_MONITORING_LSEEK,b);
		while(!p->monitored.lseek);
	}
	else if(sys == SYS_READ){
		sndmsg(p->msgid,MSG_MONITORING_READ,b);
		while(!p->monitored.read);
	}
	else if(sys == SYS_WRITE){
		sndmsg(p->msgid,MSG_MONITORING_WRITE,b);
		while(!p->monitored.write);
	}
	else if(sys == SYS_STAT){
		sndmsg(p->msgid,MSG_MONITORING_STAT,b);
		while(!p->monitored.stat);
	}
}

