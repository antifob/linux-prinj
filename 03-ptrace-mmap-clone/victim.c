/*
 *
 */

#include <sys/types.h>
#include <unistd.h>

#include <stdio.h>


int main(void)
{
	pid_t pid = getpid();

	do {
		printf("pid %u: sleeping\n", pid);
		sleep(1);
	} while (0 != 1);
}
