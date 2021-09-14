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

struct ring_buffer *rb = NULL;
struct ctester_bpf *skel;
  
static struct env {
    bool verbose;
} env;

int init_sandbox(int argc, char **argv);

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

static void record_event(struct event *e){
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
    return 0;
}


int main(int argc, char **argv){
    int err = init_sandbox(argc, argv); 
    if(err < 0){
        fprintf(stderr, "Failed start the test %d\n", err);
    }
  
    SET_MONITORED_PID(getpid());
    MONITORING(read,true);
    MONITORING(write,true);
    MONITORING(creat,true);
    
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
        BEGIN_SANDBOX;
        int fd = creat("test.txt", 0);
        END_SANDBOX;
    }
cleanup:
	/* Clean up */
    ring_buffer__free(rb);
    ctester_bpf__destroy(skel);

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

}
