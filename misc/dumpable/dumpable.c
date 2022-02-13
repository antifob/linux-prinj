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

#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdio.h>


int main(int argc, const char* const* argv)
{
	pid_t pid;


	if (0 > prctl(PR_SET_DUMPABLE, 0)) {
		perror("Failed to set process not dumpable");
		return 1;
	}

	pid = getpid();
	printf("You may run 'strace -p %i' to attach to me\n", pid);

	sleep(3600);

	return 0;
}
