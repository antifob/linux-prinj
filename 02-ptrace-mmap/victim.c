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


int main(void)
{
	pid_t pid;

	if (0 > prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)) {
		perror("Failed to disable injection protections");
		return -1;
	}

	pid = getpid();

	do {
		printf("pid %u: sleeping\n", pid);
		sleep(1);
	} while (0 != 1);
}
