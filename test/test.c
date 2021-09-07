
#include <stdio.h>
#include <stdlib.h>
#include "../CTesterLib/CTester.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(){

	int fd = 0;
	void* ctx = CTESTER_INIT_CTX();
	CTESTER_SANDBOX_ENTER(ctx);
	fd = open("essai.txt",O_CREAT|O_RDWR);
	CTESTER_SANDBOX_EXIT(ctx);
	return 0;
}
