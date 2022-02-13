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

#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>


static void dumpregs(const struct user_regs_struct* regs)
{
#define PRREG(r)	printf("%s=%016llx\n", #r, regs->r);

	PRREG(rax);
	PRREG(rbx);
	PRREG(rcx);
	PRREG(rdx);
	PRREG(rdi);
	PRREG(rsi);
	PRREG(rbp);
	PRREG(rsp);
	PRREG(rip);
	PRREG(r8);
	PRREG(r9);
	PRREG(r10);
	PRREG(r11);
	PRREG(r12);
	PRREG(r13);
	PRREG(r14);
	PRREG(r15);
}


int main(int argc, const char* const* argv)
{
	pid_t pid;
	struct user_regs_struct regs;


	if (2 != argc) {
		fprintf(stderr, "usage: seize <pid>\n");
		return 1;
	}

	pid = atoi(argv[1]);

	if (0 != ptrace(PTRACE_SEIZE, pid, 0, 0)) {
		perror("Failed to seize the target process");
		return 1;
	}

	if (0 != ptrace(PTRACE_INTERRUPT, pid, 0, 0)) {
		perror("Failed to interrupt process");
	}

	/* Wait for the process to be stopped (under our control). */
	if (pid != waitpid(pid, 0, 0)) {
		perror("Failed waiting for target process");
		return 1;
	}

	/* Get the target process's current registers. */
	if (0 != ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
		perror("Failed to read registers");
		return 1;
	}

	dumpregs(&regs);

	/* Let the target process execute normally. */
	if (0 != ptrace(PTRACE_DETACH, pid, 0, 0)) {
		perror("Failed to detach process");
		return 1;
	}

	return 0;
}
