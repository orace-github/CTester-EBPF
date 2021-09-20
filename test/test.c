
#include <stdio.h>
#include <stdlib.h>
#include "../CTesterLib/CTester.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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
