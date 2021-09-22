#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include "ctester.h"
#include "core.h"
#include "ctester.skel.h"
#include "../CTesterLib/CTester.h"

struct ring_buffer *rb = NULL;
struct ctester_bpf *skel;
void *shm = NULL;
static int qid;
volatile process_metadata* process = NULL; // monitored process

static struct env {
    bool verbose;
} env;

int init_sandbox(int argc, char **argv);
int install_sysv_shared_memory();
int install_sysv_msg();
void uninstall_sysv_shared_memory(void);
void uninstall_sysv_msg();
void probe_msg_queue();

const char *argp_program_version = "ctester 0.0";
const char *argp_program_bug_address = "<assogba.emery@gmail.com>";
const char argp_program_doc[] =
    "BPF ctester demo application.\n"
    "\n"
    "It a framework based on CUnit to test inginious task based on C language \n"
    "USAGE: ./ctester  [-v]\n";

static const struct argp_option opts[] = {
  { "verbose", 'v', NULL, 0, "Verbose debug output" },
  {},
};


static error_t parse_arg(int key, char *arg, struct argp_state *state){
    switch (key) {
        case 'v':
            env.verbose = true;
            break;
        case ARGP_KEY_ARG:
            argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
  .options = opts,
  .parser = parse_arg,
  .doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void){
    struct rlimit rlim_new = {
        .rlim_cur	= RLIM_INFINITY,
        .rlim_max	= RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

static void record_event(const struct event *e){
    fprintf(stderr, "captured: %d from %d\n", e->type, e->pid);
}

static int handle_event(void *ctx, void *data, size_t data_sz){
    const struct event *e = (struct event *)data;
    struct tm *tm;
    char ts[32];
    time_t t;
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);   
    record_event(e);
    if(e->type == SYS_ENTER_OPEN){
        process->fs.open.called++;
        process->fs.open.last_params.pathname = (char*)e->args.enter_open_args.filename_ptr;
        process->fs.open.last_params.mode = e->args.enter_open_args.mode;
        process->fs.open.last_params.flags = e->args.enter_open_args.flags;
    }
    else if(e->type == SYS_EXIT_OPEN){
        process->fs.open.last_return = e->args.exit_open_args.ret;
    }
    else if(e->type == SYS_ENTER_WRITE){
        process->fs.write.called++;
        process->fs.write.last_params.buf = (void*)e->args.enter_write_args.buf;
        process->fs.write.last_params.count = e->args.enter_write_args.count;
        process->fs.write.last_params.fd = e->args.enter_write_args.fd;
    }
    else if(e->type == SYS_EXIT_WRITE){
        process->fs.write.last_return = e->args.exit_write_args.ret;
    }
    else if(e->type == SYS_ENTER_READ){
        process->fs.read.called++;
        process->fs.read.last_params.buf = (void*)e->args.enter_read_args.buf;
        process->fs.read.last_params.count = e->args.enter_read_args.count;
        process->fs.read.last_params.fd = e->args.enter_read_args.fd;
    }
    else if(e->type == SYS_EXIT_READ){
        process->fs.read.last_return = e->args.exit_read_args.ret;
    }
    else if(e->type == SYS_CLOSE){
        process->fs.close.called++;
        process->fs.close.last_params.fd = e->args.enter_close_args.fd;
    }
    else if(e->type == SYS_EXIT_CLOSE){
        process->fs.close.last_return = e->args.exit_close_args.ret;
    }
    else if(e->type == SYS_CREAT){
        process->fs.creat.called++;
        process->fs.creat.last_params.mode = e->args.enter_creat_args.mode;
        process->fs.creat.last_params.pathname = (char*)e->args.enter_creat_args.filename_ptr;
    }
    else if(e->type == SYS_EXIT_CREAT){
        process->fs.creat.last_return = e->args.exit_creat_args.ret;
    }
    else if(e->type == SYS_ENTER_STAT){
        process->fs.stat.called++;
        process->fs.stat.last_params.buf = (struct stat*)e->args.enter_stat_args.statbuf;
        process->fs.stat.last_params.path = (char*)e->args.enter_stat_args.filename_ptr;
    }
    else if(e->type == SYS_EXIT_STAT){
        process->fs.stat.last_return = e->args.exit_stat_args.ret;
    }
    else if(e->type == SYS_ENTER_FSTAT){
        process->fs.fstat.called++;
        process->fs.fstat.last_params.buf = (struct stat*)e->args.enter_fstat_args.statbuf;
        process->fs.fstat.last_params.fd = e->args.enter_fstat_args.fd;
    }
    else if(e->type == SYS_EXIT_STAT){
        process->fs.fstat.last_return = e->args.exit_fstat_args.ret;
    }
    else if(e->type == SYS_ENTER_LSEEK){
        process->fs.lseek.called++;
        process->fs.lseek.last_params.fd = e->args.enter_lseek_args.fd;
        process->fs.lseek.last_params.offset = e->args.enter_lseek_args.offset;
        process->fs.lseek.last_params.whence = e->args.enter_lseek_args.whence;
    }
    else if(e->type == SYS_EXIT_LSEEK){
        process->fs.lseek.last_return = e->args.exit_lseek_args.ret;
    }
    return 0;
}

int main(int argc, char **argv){
    int err = init_sandbox(argc, argv); 
    if(err < 0){
        fprintf(stderr, "Failed start the test %d\n", err);
    }
    
    //SET_MONITORED_PID(getpid());
    //MONITORING(read,true);
    //MONITORING(write,true);
    //MONITORING(creat,true);
    
    while (!skel->bss->ctester_cfg.end_student_code) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
        probe_msg_queue();
        //BEGIN_SANDBOX;
        //int fd = creat("test.txt", 0);
        //END_SANDBOX;
    }
	/* Clean up */
    ring_buffer__free(rb);
    ctester_bpf__destroy(skel);
    uninstall_sysv_shared_memory();
    uninstall_sysv_msg();
    return err < 0 ? -err : 0;
}


int init_sandbox(int argc, char **argv){
    int err;
    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);
    /* Bump RLIMIT_MEMLOCK to create BPF maps */
    bump_memlock_rlimit();
    /* Load and verify BPF application */
    skel = ctester_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }
    /* Load & verify BPF programs */
    err = ctester_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        return err;
    }

    /* Attach tracepoints */
    err = ctester_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        return err;
    }
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        return err;
    }
    /* Set shared memory */
    err = install_sysv_shared_memory();
    if(err < 0){
        fprintf(stderr, "shared memory installation failed");
        return err;
    }

    /* Set sysv msg */
    err = install_sysv_msg();
    if(err < 0){
        fprintf(stderr, "sysv msg installation failed");
        return err;
    }
    return 0;
}

int install_sysv_shared_memory()
{
    /* shared memory */
    int shmID;
    shmID = shmget(CTESTER_SHM_KEY, CTESTER_SHM_SIZE,
                   CTESTER_SHM_PERM | IPC_CREAT);
    if(shmID < 0){
        return -1;
    }
    shm_metadata *shmPTR = (shm_metadata *)shmat(shmID, NULL, 0);
    shmPTR->count = 0;
    bzero(shmPTR->data, (CTESTER_SHM_SIZE - sizeof(*shmPTR)));
    shm = shmPTR;
    return 0;
}

void uninstall_sysv_shared_memory(void){
    if(shm){
        shmdt(shm);
    }
}

void uninstall_sysv_msg(){
    msgctl(qid,IPC_RMID,NULL);
}

int install_sysv_msg(){
    /* msg */
    int id;
    id = msgget(CTESTER_MSG_KEY,IPC_CREAT|CTESTER_MSG_PERM);
    if(id == -1)
        return -1;
    qid = id;
    return 0;
}

void probe_msg_queue(){
    // wait for monitoring process, to register in shared memory
    shm_metadata* shmdata = (shm_metadata*)(shm);
    while(!shmdata->count);
    process_metadata* pm = (process_metadata*)(shmdata->data);
    process = &pm[shmdata->count - 1];
    
    struct msgbuf msg;
    process_t* p;
    bool b;
    if(receivemsg(qid,sys_enable_sandbox,&msg) != -1){
        p = (process_t*)msg.mtext;
        SET_MONITORED_PID(p->pid);
        BEGIN_SANDBOX;
        process->monitor_sys_enable_sandbox = 1;
    }
    if(receivemsg(qid,sys_disable_sandbox,&msg) != -1){
        p = (process_t*)msg.mtext;
        END_SANDBOX;
        process->monitor_sys_enable_sandbox = 0;
    }
    if(receivemsg(qid,sys_creat,&msg) != -1){
        fprintf(stderr,"recv creat msg\n");
        b = (bool)msg.mtext[0];
        MONITORING(creat,b);
        process->monitor_sys_creat = (b) ? 1 : 0;
    }
    
    if(receivemsg(qid,sys_read,&msg) != -1){
        fprintf(stderr,"recv read msg\n");
        b = (bool)msg.mtext[0];
        MONITORING(read,b);
        process->monitored.read = (b) ? 1 : 0;
    }
    
    if(receivemsg(qid,sys_write,&msg) != -1){
        fprintf(stderr,"recv write msg\n");
        b = (bool)msg.mtext[0];
        MONITORING(write,b);
        process->monitored.write = (b) ? 1 : 0;
    }
    
    if(receivemsg(qid,sys_open,&msg) != -1){
        fprintf(stderr,"recv open msg\n");
        b = (bool)msg.mtext[0];
        MONITORING(open,b);
        process->monitored.open = (b) ? 1 : 0;
    }
    
    if(receivemsg(qid,sys_close,&msg) != -1){
        fprintf(stderr,"recv close msg\n");
        b = (bool)msg.mtext[0];
        MONITORING(close,b);
        process->monitored.close = (b) ? 1 : 0;
    }
    
    if(receivemsg(qid,sys_fstat,&msg) != -1){
        fprintf(stderr,"recv fstat msg\n");
        b = (bool)msg.mtext[0];
        MONITORING(fstat,b);
        process->monitored.fstat = (b) ? 1 : 0;
    }
    if(receivemsg(qid,sys_lseek,&msg) != -1){
        fprintf(stderr,"recv lseek msg\n");
        b = (bool)msg.mtext[0];
        MONITORING(lseek,b);
        process->monitored.lseek = (b) ? 1 : 0;
    }
}
