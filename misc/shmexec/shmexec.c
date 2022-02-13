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

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, const char* const* argv)
{
	int fd;
	int shmid;
	void* shmaddr;
	struct stat st;


	if (2 != argc) {
		fprintf(stderr, "usage: shmexec <shellcode.file>\n");
		return 1;
	}

	if (0 > (fd = open(argv[1], O_RDONLY))) {
		perror("Failed to open file");
		return 1;
	}

	if (0 > fstat(fd, &st)) {
		perror("Failed to get shellcode size");
		return 1;
	}

	/* Allocate anonymous shm and mark as rwx-able. */
	if (0 > (shmid = shmget(IPC_PRIVATE, st.st_size, IPC_CREAT | 0700))) {
		perror("Failed to allocate shm");
		return 1;
	}

	/* Get shm address and mark executable. */
	if (((void*)-1) == (shmaddr = shmat(shmid, 0, SHM_EXEC))) {
		perror("Failed to get shm address");
		return 1;
	}

	if (st.st_size != read(fd, shmaddr, st.st_size)) {
		perror("Failed to copy shellcode");
		return 1;
	}

	/* Execute shellcode. */
	((void(*)(void))shmaddr)();

	return 0;
}
