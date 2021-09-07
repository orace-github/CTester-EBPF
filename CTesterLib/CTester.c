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
	if(((CTESTER_SHM_SIZE-(sizeof(shm_metadata)))/sizeof(process_metadata)) < shm->offset )
		return NULL;

	process_metadata* p = (process_metadata*)(shm->data);
	// look from umaped buffer
	for(int i = 0; i < shm->offset; i++){
		if(!p[i].cmaped && !p[i].lmaped)
			return &p[i];
	}
	process_metadata* pp = &p[shm->offset];
	shm->offset++;
	return pp;
}

void shm_free(process_metadata* p){
	if(!p)
        return;
	p->cmaped = 0;
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
	
    // - process context
	process_metadata* p = shm_malloc(shm);
	if(!p)
		return NULL;

	p->cmaped = 0;
    p->lmaped = 0;
	p->shm = shm;
	p->ctx = (void*)p;
	
    return p->ctx;
}

int CTESTER_ADD_PROCESS(CTESTER_CTX ctx)
{
    if(!ctx) 
		return -1;
	// - get process pid gid
	int pid = getpid();
	int gid = getgid();
    process_metadata* p = (process_metadata*)ctx;
    p->p.monitoring = true;
	p->p.pid = pid;
	p->p.gid = gid;
    p->lmaped = 1; // lib map it then wait for CTester deamon to map it to
	p->cmaped = 0;
    while(!p->cmaped);// wait untill CTester deamon set this field to 1
    p->m_map = p;
	return 0;
}

int CTESTER_REMOVE_PROCESS(CTESTER_CTX ctx)
{
    if(!ctx) 
		return -1;
	// - get process pid gid
	process_metadata* p = (process_metadata*)ctx;
	p->lmaped = 0;
    while(p->cmaped);
    return 0;
}

int CTESTER_RELEASE_CTX(CTESTER_CTX ctx)
{
    if(!ctx) 
		return -1;
	// - get process pid gid
	process_metadata* p = (process_metadata*)ctx;
	p->lmaped = 0;
    CTESTER_REMOVE_PROCESS(ctx);
    p->cmaped = 0;

    return 0;
}

void CTESTER_SET_MONITORING(CTESTER_CTX ctx, unsigned int fs_flags)
{
    if(!ctx) 
		return;
	// - get process pid gid
	process_metadata* p = (process_metadata*)ctx;
	p->fs_flags = fs_flags;
    // set flags
    p->fs.monitor.monitoring_close = (fs_flags & MONITORING_CLOSE) ? true : false;
    p->fs.monitor.monitoring_creat = (fs_flags & MONITORING_CREAT) ? true : false;
    p->fs.monitor.monitoring_open = (fs_flags & MONITORING_OPEN) ? true : false;
    p->fs.monitor.monitoring_read = (fs_flags & MONITORING_READ) ? true : false;
    p->fs.monitor.monitoring_write = (fs_flags & MONITORING_WRITE) ? true : false;
    p->fs.monitor.monitoring_stat = (fs_flags & MONITORING_STAT) ? true : false;
    p->fs.monitor.monitoring_fstat = (fs_flags & MONITORING_FSTAT) ? true : false;
    p->fs.monitor.monitoring_lseek = (fs_flags & MONITORING_LSEEK) ? true : false;    
}
