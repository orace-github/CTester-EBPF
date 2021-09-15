// SPDX-License-Identifier: GPL-2.0-or-later
//
// CTester - syscall statistics with EBPF
// Copyright (C) 2021  Orace KPAKPO
// Sep, 02 2021 Orace KPAKPO  Created this.

#include "CTester.h"

// CTester shared memory helper
process_metadata* shm_malloc(shm_metadata* shm)
{
	// - check memory boundary
	if(((CTESTER_SHM_SIZE-(sizeof(shm_metadata)))/sizeof(process_metadata)) < shm->count )
		return NULL;

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

int sendmsg(int qid, long msgtype, bool b){
	struct msgbuf buf;
	int err;
	if(msgtype == MSG_MONITORING_CLOSE){
		buf.mtype = MSG_MONITORING_CLOSE;
		buf.mtext[0] = (char)b;
		err = msgsnd(qid,&buf,sizeof(buf.mtext),IPC_NOWAIT);
		if(err)
			return err;
	}
	if(msgtype == MSG_MONITORING_CREAT){
		buf.mtype = MSG_MONITORING_CREAT;
		buf.mtext[0] = (char)b;
		err = msgsnd(qid,&buf,sizeof(buf.mtext),IPC_NOWAIT);
		if(err)
			return err;
	}
	else if(msgtype == MSG_MONITORING_FSTAT){
		buf.mtype = MSG_MONITORING_FSTAT;
		buf.mtext[0] = (char)b;
		err = msgsnd(qid,&buf,sizeof(buf.mtext),IPC_NOWAIT);
		if(err)
			return err;
	}
	else if(msgtype == MSG_MONITORING_LSEEK){
		buf.mtype = MSG_MONITORING_LSEEK;
		buf.mtext[0] = (char)b;
		err = msgsnd(qid,&buf,sizeof(buf.mtext),IPC_NOWAIT);
		if(err)
			return err;
	}
	else if(msgtype == MSG_MONITORING_OPEN){
		buf.mtype = MSG_MONITORING_OPEN;
		buf.mtext[0] = (char)b;
		err = msgsnd(qid,&buf,sizeof(buf.mtext),IPC_NOWAIT);
		if(err)
			return err;
	}
	else if(msgtype == MSG_MONITORING_READ){
		buf.mtype = MSG_MONITORING_READ;
		buf.mtext[0] = (char)b;
		err = msgsnd(qid,&buf,sizeof(buf.mtext),IPC_NOWAIT);
		if(err)
			return err;
	}
	else if(msgtype == MSG_MONITORING_STAT){
		buf.mtype = MSG_MONITORING_STAT;
		buf.mtext[0] = (char)b;
		err = msgsnd(qid,&buf,sizeof(buf.mtext),IPC_NOWAIT);
		if(err)
			return err;
	}
	else if(msgtype == MSG_MONITORING_WRITE){
		buf.mtype = MSG_MONITORING_WRITE;
		buf.mtext[0] = (char)b;
		err = msgsnd(qid,&buf,sizeof(buf.mtext),IPC_NOWAIT);
		if(err)
			return err;
	}
	else if(msgtype == MSG_MONITORING_PID){
		buf.mtype = MSG_MONITORING_PID;
		process_t p;
		p.gid = getgid();
		p.pid = getpid();
		memcpy(buf.mtext,&p,sizeof(buf.mtext));
		err = msgsnd(qid,&buf,sizeof(buf.mtext),IPC_NOWAIT);
		if(err)
			return err;
	}
	else if(msgtype == MSG_UNMONITORING_PID){
		buf.mtype = MSG_UNMONITORING_PID;
		process_t p;
		p.gid = getgid();
		p.pid = getpid();
		memcpy(buf.mtext,&p,sizeof(buf.mtext));
		err = msgsnd(qid,&buf,sizeof(buf.mtext),IPC_NOWAIT);
		if(err)
			return err;
	}
	return 0;
}

int recvmsg(int qid, long msgtype, struct msgbuf* buf){
	int err;
	err = msgrcv(qid,buf,sizeof(buf->mtext),msgtype,MSG_NOERROR|IPC_NOWAIT);
	if(err)
		return -1;
	return 0;
}


CTESTER_CTX CTESTER_INIT_CTX(void){
    // TODO
	// - get shared memory
	int shmID;
	shmID = shmget(CTESTER_SHM_KEY,CTESTER_SHM_SIZE,CTESTER_SHM_PERM);
	if(shmID < 0)				
		return NULL;
	shm_metadata* shm = (shm_metadata*)shmat(shmID,NULL,0);
	
    if(shm == (void*)-1)
		return NULL;
	
	// msg sysv
	/* msg */
    int id;
    id = msgget(CTESTER_MSG_KEY,CTESTER_MSG_PERM);
    if(id == -1){
        return NULL;
    }

    // - process context
	process_metadata* p = shm_malloc(shm);
	if(!p)
		return NULL;
	// clear all flags
	memset(&p->monitored,0,sizeof(p->monitored));
	p->shm = shm;
	p->msgid = id;
	p->ctx = (void*)p;
	
    return p->ctx;
}

int CTESTER_ADD_PROCESS(CTESTER_CTX ctx)
{
    if(!ctx) 
		return -1;
	process_metadata* p = (process_metadata*)ctx;
	sendmsg(p->msgid,MSG_MONITORING_PID,true);
	while(!p->monitored.pid);
   	return 0;
}

int CTESTER_REMOVE_PROCESS(CTESTER_CTX ctx)
{
    if(!ctx) 
		return -1;
	// - get process pid gid
	process_metadata* p = (process_metadata*)ctx;
	sendmsg(p->msgid,MSG_UNMONITORING_PID,true);
	while(p->monitored.pid);
	return 0;
}

int CTESTER_RELEASE_CTX(CTESTER_CTX ctx)
{
    if(!ctx) 
		return -1;
	// - get process pid gid
	process_metadata* p = (process_metadata*)ctx;
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
		sendmsg(p->msgid,MSG_MONITORING_OPEN,b);
		while(!p->monitored.open);
	}
	else if(sys == SYS_CLOSE){
		sendmsg(p->msgid,MSG_MONITORING_CLOSE,b);
		while(!p->monitored.close);
	}
	else if(sys == SYS_CREAT){
		sendmsg(p->msgid,MSG_MONITORING_CREAT,b);
		while(!p->monitored.creat);
	}
	else if(sys == SYS_FSTAT){
		sendmsg(p->msgid,MSG_MONITORING_FSTAT,b);
		while(!p->monitored.fstat);
	}
	else if(sys == SYS_LSEEK){
		sendmsg(p->msgid,MSG_MONITORING_LSEEK,b);
		while(!p->monitored.lseek);
	}
	else if(sys == SYS_READ){
		sendmsg(p->msgid,MSG_MONITORING_READ,b);
		while(!p->monitored.read);
	}
	else if(sys == SYS_WRITE){
		sendmsg(p->msgid,MSG_MONITORING_WRITE,b);
		while(!p->monitored.write);
	}
	else if(sys == SYS_STAT){
		sendmsg(p->msgid,MSG_MONITORING_STAT,b);
		while(!p->monitored.stat);
	}
}

