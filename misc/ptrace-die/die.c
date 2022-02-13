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
#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>


int main(int argc, const char* const* argv)
{
	pid_t pid;


	if (2 != argc) {
		fprintf(stderr, "usage: die <pid>\n");
		return 1;
	}

	pid = atoi(argv[1]);

	if (0 != ptrace(PTRACE_ATTACH, pid, 0, 0)) {
		perror("Failed to seize the target process");
		return 1;
	}

	/* Wait for the process to be stopped (under our control). */
	if (pid != waitpid(pid, 0, 0)) {
		perror("Failed waiting for target process");
		return 1;
	}

	/* do not detach and exit */

	return 0;
}
