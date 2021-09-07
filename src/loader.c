// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Orace KPAKPO */
#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/timerfd.h>
#include "ctester.skel.h"
#include <CTester.h>

/* bpf uprobe command used by CTester lib */
int ctester_add_process(process_t* p, unsigned int fs_flags, long* ret_p){};
int ctester_rm_process(process_t* p, fs_wrap_stats_t* fs, long* ret_p){};

/* Expand ressource limit */
static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
    {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(EXIT_FAILURE);
    }
}

/* Signal handler */
static volatile bool exiting = false;
static void sig_handler(int sig)
{
    if (sig == SIGTERM)
        printf("\nSIGTERM triggered \n");
    else if (sig == SIGINT)
        printf("\nSIGINT triggered \n");

    exiting = true;
}

/* Find process's base load address. We use /proc/self/maps for that,
 * searching for the first executable (r-xp) memory mapping:
 *
 * 5574fd254000-5574fd258000 r-xp 00002000 fd:01 668759                     /usr/bin/cat
 * ^^^^^^^^^^^^                   ^^^^^^^^
 *
 * Subtracting that region's offset (4th column) from its absolute start
 * memory address (1st column) gives us the process's base load address.
 */
static long get_base_addr()
{

    size_t start, offset;
    char buf[256];
    FILE *f;

    f = fopen("/proc/self/maps", "r");
    if (!f)
        return -errno;

    while (fscanf(f, "%zx-%*x %s %zx %*[^\n]\n", &start, buf, &offset) == 3)
    {
        if (strcmp(buf, "r-xp") == 0)
        {
            fclose(f);
            return start - offset;
        }
    }

    fclose(f);
    return -1;
}

/* load bpf code in kernel memory
 * 
 * load and attach container bpf routine 
 * exit process if any error occurs,
 * otherwise bpf code skeleton 
 */

static struct ctester_bpf *load_bpf_code(void)
{

    struct ctester_bpf *skel;
    long base_addr, add_offset, rm_offset;
    int err, i;

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    /* Load and verify BPF application */
    skel = ctester_bpf__open_and_load();
    if(!skel){
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        ctester_bpf__destroy(skel);
        exit(EXIT_FAILURE);
    }

    err = ctester_bpf__attach(skel);

    if(err)
        fprintf(stderr, "failed to attach tracepoint\n");

    base_addr = get_base_addr();
    if(base_addr < 0){
        fprintf(stderr, "Failed to determine process's load address\n");
        err = base_addr;
        ctester_bpf__destroy(skel);
        exit(EXIT_FAILURE);
    }

    /* uprobe/uretprobe expects relative offset of the function to attach
	 * to. This offset is relative to the process's base load address. So
	 * easy way to do this is to take an absolute address of the desired
	 * function and substract base load address from it.  If we were to
	 * parse ELF to calculate this function, we'd need to add .text
	 * section offset and function's offset within .text ELF section.
	 */
    add_offset = (long)&ctester_add_process - base_addr;
    rm_offset = (long)&ctester_rm_process - base_addr;

    /* Attach tracepoint handler */
    skel->links.ctester_add_process = bpf_program__attach_uprobe(skel->progs.ctester_add_process,
                                                             false /* not uretprobe */,
                                                             0 /* self pid */,
                                                             "/proc/self/exe",
                                                             add_offset);
    err = libbpf_get_error(skel->links.ctester_add_process);
    if(err){
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        ctester_bpf__destroy(skel);
        exit(EXIT_FAILURE);
    }

    skel->links.ctester_rm_process = bpf_program__attach_uprobe(skel->progs.ctester_rm_process,
                                                             false /* not uretprobe */,
                                                             0 /* self pid */,
                                                             "/proc/self/exe",
                                                             rm_offset);
    err = libbpf_get_error(skel->links.ctester_rm_process);
    if(err){
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        ctester_bpf__destroy(skel);
        exit(EXIT_FAILURE);
    }

    return skel;
}

/* install shared memory
 * 
 * @progname is required to setting up memory field
 * setting up and install container shared memory 
 */
static struct{
    int ID;
    shm_metadata *ptr;
} shared_memory = {
    .ID = -1,
    .ptr = NULL,
};

static void install_sysv_shared_memory()
{
    /* shared memory */
    int shmID;
    shmID = shmget(CTESTER_SHM_KEY, CTESTER_SHM_SIZE,
                   CTESTER_SHM_PERM | IPC_CREAT);
    if(shmID < 0){
        fprintf(stderr, "shared memory installation failed");
        return;
    }
    shm_metadata *shmPTR = (shm_metadata *)shmat(shmID, NULL, 0);
    shmPTR->shm_key = CTESTER_SHM_KEY;
    shmPTR->shm_size = CTESTER_SHM_SIZE;
    shmPTR->offset = 0;
    bzero(shmPTR->data, (CTESTER_SHM_SIZE - sizeof(*shmPTR)));
    shared_memory.ID = shmID;
    shared_memory.ptr = shmPTR;
}

/* uninstall shared memory
 * free kernel memory ressource
 */

static void uninstall_sysv_shared_memory(void){
    if(shared_memory.ptr){
        shmdt((void *)shared_memory.ptr);
    }
}

/* setting up timer
 *
 * make_periodic and wait_periodic
 * inspired from link: git@github.com:csimmonds/periodic-threads.git
 * this section of code is a part of 90%
 */

struct periodic_info
{
    int timer_fd;
    unsigned long long wakeups_missed;
};

static int make_periodic(unsigned int period, struct periodic_info *info)
{
    int ret;
    unsigned int ns;
    unsigned int sec;
    int fd;
    struct itimerspec itval;

/* we defined CLOCK_MONOTONIC due to invalid declaration in linux kernel header 5.11.0 */
#define CLOCK_MONOTONIC 1 // TODO
    /* Create the timer */
    fd = timerfd_create(CLOCK_MONOTONIC, 0);
    info->wakeups_missed = 0;
    info->timer_fd = fd;
    if (fd == -1)
        return fd;

    /* Make the timer periodic */
    sec = period / 1000000;
    ns = (period - (sec * 1000000)) * 1000;
    itval.it_interval.tv_sec = sec;
    itval.it_interval.tv_nsec = ns;
    itval.it_value.tv_sec = sec;
    itval.it_value.tv_nsec = ns;
    ret = timerfd_settime(fd, 0, &itval, NULL);
    return ret;
}

static void wait_period(struct periodic_info *info)
{
    unsigned long long missed;
    int ret;

    /* Wait for the next timer event. If we have missed any the
	   number is written to "missed" */
    ret = read(info->timer_fd, &missed, sizeof(missed));
    if (ret == -1)
    {
        fprintf(stderr, "read timer");
        return;
    }

    info->wakeups_missed += missed;
}

// basic structure of container thread to explore shared memory
static struct{
    void (*func)(shm_metadata *shm);
    shm_metadata *shm;
} shmthread;

static void *thread(void *arg)
{
    struct periodic_info info;
    // set timer to 100 ms
    make_periodic(100000, &info);
    while(1)
    {
        shmthread.func(shmthread.shm);
        wait_period(&info);
    }
    return NULL;
}

void probing_sysv_shared_memory(shm_metadata *shm){

    process_metadata *p = (process_metadata *)shm->data;
    long ret = 0;
    // -- probing memory
    for (int i = 0; i < shm->offset; i++){
        // look for maped process
        if (p[i].lmaped && (!p[i].cmaped)){
            ctester_add_process(&p[i].p, p[i].fs_flags, &ret);
            p[i].cmaped = (ret == 0) ? 1 : 0;
        }
        else if(!p[i].lmaped){
            if(p[i].cmaped){
                ctester_rm_process(&p[i].p, &p[i].fs, &ret);
                p[i].cmaped = (ret == 0) ? 0 : 1;
            }
        }
    }

}

int main(int argc, char **argv)
{

    struct ctester_bpf *skel;
    /* load bpf code */
    skel = load_bpf_code();
    /* install shared memory */
    install_sysv_shared_memory();
    /* signal */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);    
    /* pthread */
    shmthread.func = probing_sysv_shared_memory;
    shmthread.shm = shared_memory.ptr;
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, thread, NULL);
    // handle SIGINT 
    while(1){
        if(exiting)
            break;
    }
    uninstall_sysv_shared_memory();
    ctester_bpf__destroy(skel);
    return 0;
}
