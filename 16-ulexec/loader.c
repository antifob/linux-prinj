/*
 * This file is part of the linux-prinj project.
 * https://gitlab.com/pgregoire/linux-prinj/
 *
 * Copyright 2021-2022 Philippe Grégoire <git@pgregoire.xyz>
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

#include <sys/mman.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>


int main(int argc, const char* const* argv)
{
	int fd;
	void (*p)(void);
	struct stat st;

	if (2 != argc) {
		fprintf(stderr, "usage: loader file\n");
		return 1;
	}

	if (0 > (fd = open(argv[1], O_RDONLY))) {
		perror("open");
		return 1;
	}

	if (0 != stat(argv[1], &st)) {
		perror("fstat");
		return 1;
	}

	p = mmap(0, st.st_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (MAP_FAILED == p) {
		perror("mmap");
		return 1;
	}

	if (st.st_size != read(fd, p, st.st_size)) {
		perror("read");
		return 1;
	}

	if (0 != mprotect(p, st.st_size, PROT_READ|PROT_EXEC)) {
		perror("mprotect");
		return 1;
	}

	p();

	return 0;
}
