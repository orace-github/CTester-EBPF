
#include <stdio.h>
#include <stdlib.h>
#include "../CTesterLib/CTester.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int myfunc(int myargs);

int my_open_func(int args){
    int fd = open("config.data",O_CREAT);
    return fd;
}

int my_exec_func(int args){
    int err = execv("/usr/bin/bash",NULL);
}

int my_creat_func(int args){
    int err = creat("log.data",S_IRUSR|S_IWUSR);
    return err;
}

int my_close_func(int args){
    int err = close(0);
}

int my_write_func(int args){
    return write(0,"Hello, World\n", 25);
}

int my_read_func(int args){
    char tmp[25];
    return read(1,tmp,25);
}

int my_stat_func(int args){
    struct stat buf;
    return stat("/usr/bin/bash",&buf);
}

int my_fstat_func(int args){
    struct stat buf;
    return fstat(0,&buf);
}

int my_lseek_func(int args){
    return lseek(0,SEEK_SET,0);
}

int my_getpid_func(int args){
    return getpid();
}

int main(){
    int fd = 0;
    void* ctx; 
    ctx = CTESTER_INIT_CTX();
    
    CTESTER_SET_MONITORING(ctx,SYS_CREAT,true);
    CTESTER_SET_MONITORING(ctx,SYS_WRITE,true);
    CTESTER_SET_MONITORING(ctx,SYS_LSEEK,true);
    CTESTER_SANDBOX_ENTER(ctx);
    fd = creat("essai.txt",0);
    lseek(fd, 0, SEEK_CUR);
    int err = write(fd, "essai.txt",10);
    CTESTER_SANDBOX_EXIT(ctx);
    
    CTESTER_SET_MONITORING(ctx,SYS_CLOSE,true);
    CTESTER_SET_MONITORING(ctx,SYS_OPEN,true);
    CTESTER_SANDBOX_ENTER(ctx);
    fd = open("essai.txt",0);
    close(fd);
    CTESTER_SANDBOX_EXIT(ctx);
    
    fprintf(stderr, "I am %d\n", getpid());
    
    CTESTER_RELEASE_CTX(ctx);
    return 0;
}
