/*
 * This file is part of the linux-prinj project.
 * https://gitlab.com/pgregoire/linux-prinj/
 *
 * Copyright 2022 Philippe Grégoire <git@pgregoire.xyz>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _XOPEN_SOURCE 700

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static void prbuf(const void* buf, size_t len)
{
	size_t i;

	for (i = 0 ; i < len ; /**/) {
		printf("%02hhx", ((unsigned char*)buf)[i++]);
		if (0 == (i % 16)) {
			putchar('\n');
		} else if (0 == (i % 2)) {
			putchar(' ');
		}
	}

	printf("\n\n");
}


static int
rdmem(pid_t pid, unsigned long addr, unsigned char* buf, size_t len)
{
	size_t i;
	unsigned long v;

	for (i = 0 ; i < len ; /**/) {
		v = ptrace(PTRACE_PEEKUSER, pid, addr, 0);
		if (0 != errno) {
                        return -1;
                }

		*((unsigned long*)(&buf[i])) = v;

                i += sizeof(unsigned long);
                addr += sizeof(unsigned long);
        }

        return 0;
}

/*
 * Writes the @len bytes in @buf at @addr in @pid's address space.
 */
static int
wrmem(pid_t pid, unsigned long addr, const void* buf, size_t len)
{
	size_t i;
	unsigned long v;

	for (i = 0 ; i < len ; /**/) {
		v = ((unsigned long*)buf)[i/sizeof(unsigned long)];
		printf("Writing %016llx at 0x%016llx\n", v, addr);
		if (0 != ptrace(PTRACE_POKEUSER, pid, addr, v)) {
			return -1;
		}

		i += sizeof(unsigned long);
		addr += sizeof(unsigned long);
	}

	return 0;
}


int main(int argc, const char* const* argv)
{
	pid_t pid;
	size_t len;
	unsigned char buf[4096];
	struct user_regs_struct regs;



	switch ((pid = fork())) {
	case -1:
		perror("Failed to fork");
		return 1;
	case 0: /* child */
		if (0 != ptrace(PTRACE_TRACEME, 0, 0, 0)) {
			perror("Child failed to signal traceability");
			return 1;
		}

		execl("./tracee", 0);
		perror("execl");
		return 1;
	default: /* parent */
		break;
	}

	/* Wait for the process to be stopped (under our control). */
	if (pid != waitpid(pid, 0, 0)) {
		perror("Failed waiting for target process");
		return 1;
	}

	if (0 != ptrace(PTRACE_SINGLESTEP, pid, 0, 0)) {}
	if (pid != waitpid(pid, 0, 0)) {
		perror("Failed waiting for target process");
		return 1;
	}

	/* Get the target process's current registers. */
	if (0 != ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
		perror("Failed to read registers (1)");
		return 1;
	}
	printf("rax=%016llx\n", regs.rax);

	puts("==> Dumping user_struct_regs");
	prbuf(&regs, sizeof(regs));

	/* TODO error checking */
	rdmem(pid, 0, buf, sizeof(buf));
	puts("==> Dumping USER area");
	prbuf(buf, sizeof(regs));

	if (0 == memcmp(buf, &regs, sizeof(regs))) {
		puts("Buffers are identical");
	} else {
		puts("Buffers are NOT identical");
	}
	puts("");

	/* Change rax via POKEUSER. */
	puts("==> Changing registers using POKEUSER");
	regs.rax = 0xdeadbeef;
	if (0 != wrmem(pid, 0, &regs, sizeof(regs))) {
		perror("Failed to write to memory");
		return 1;
	}

	/* Read the registers again. */
	if (0 != ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
		perror("Failed to read registers (1)");
		return 1;
	}
	printf("rax=%016llx\n", regs.rax);

	/* Let the target process execute normally. */
	if (0 != ptrace(PTRACE_DETACH, pid, 0, 0)) {
		perror("Failed to detach process");
		return 1;
	}

	if (0 != kill(pid, SIGKILL)) {
		perror("Failed to kill process");
		return 1;
	}

	return 0;
}
