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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>


static int attach(pid_t pid)
{
	if (0 != ptrace(PTRACE_SEIZE, pid, 0, 0)) {
		perror("Failed to seize the target process");
		return -1;
	}

	/* Wait for the process to be stopped (under our control). */
	if (pid != waitpid(pid, 0, 0)) {
		perror("Failed waiting for target process");
		return -1;
	}

	/* Let the target process execute normally. */
	if (0 != ptrace(PTRACE_DETACH, pid, 0, 0)) {
		perror("Failed to detach process");
		return -1;
	}

	return 0;
}


int main(int argc, const char* const* argv)
{
	pid_t pid;
	uid_t uid = getuid();
	gid_t gid = getgid();
	uid_t euid = geteuid();
	gid_t egid = getegid();



	if (2 == argc) {
		return -attach(atoi(argv[1]));
	} else if (1 != argc) {
		fprintf(stderr, "usage: ptrace [pid]\n");
		return 1;
	}

	/* We are the tracee. */
	printf("Hello from pid=%u\n", getpid());
	printf("uid/gid=%u/%u, euid/egid=%u/%u\n", uid, gid, euid, egid);
	puts("Sleeping for 60 seconds");
	sleep(60);

	return 0;
}
