#
# This file is part of the linux-prinj project.
# https://gitlab.com/pgregoire/linux-prinj/
#
# Copyright 2021-2022 Philippe Grégoire <git@pgregoire.xyz>
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

.set	STACK_SIZE, 81920

.intel_syntax noprefix
.global _start

_start:
	# To get the ELF's address, we cannot jump over the code
	# because it is too big. Simply get our current position
	# and search for it.

	call	start
start:
	pop	r15
	add	r15, 200

findelf:
	mov	eax, [r15]
	cmp	eax, 0x464c457f		# \x7fELF
	je	ulexec
	inc	r15
	jmp	findelf

# -------------------------------------------------------------------- #
# rdi = loaded elf

ulexec:
	push	rbp
	mov	rbp, rsp
	sub	rsp, 32

	mov	[rbp-8], r15		# reference elf

	mov	rax, r15
	call	loadelf
	mov	[rbp-16], rax		# mapped elf

	mov	rax, [rbp-16]
	call	loadinterp
	mov	[rbp-24], rax

	mov	rax, [rbp-16]
	mov	rbx, [rbp-24]
	call	setup_stack

	mov	rsp, rax

	mov	rax, [rbp-24]
	cmp	rax, 0
	jne	_ulexec_interp

	mov	rax, [rbp-16]
	mov	bl, [rax+16]
	mov	rax, [rax+24]
	cmp	bl, 3
	jne	_ulexec_end
	add	rax, [rbp-16]
	jmp	_ulexec_end

_ulexec_interp:
	add	rax, [rax+24]

_ulexec_end:
	push	rax
	xor	rax, rax
	xor	rbx, rbx
	xor	rcx, rcx
	xor	rdx, rdx
	xor	rdi, rdi
	xor	rsi, rsi
	xor	rbp, rbp
	xor	r8, r8
	xor	r9, r9
	xor	r10, r10
	xor	r11, r11
	xor	r12, r12
	xor	r13, r13
	xor	r14, r14
	xor	r15, r15
	ret

# -------------------------------------------------------------------- #
#
# rax = mmapped elf
# rbx = mmapped interpreter
#

swrite:
	# rsi = bytes
	# rcx = length
	mov	rdi, [rbp-40]
_swrite:
	dec	rcx
	cmp	rcx, 0
	jl	_swrite_end
	mov	al, [rsi+rcx]
	mov	[rdi+rcx], al
	jmp	_swrite

_swrite_end:
	ret

spush:
	# rax = value
	mov	rdi, [rbp-40]
	sub	rdi, 8
	mov	[rdi], rax
	mov	[rbp-40], rdi
	ret

setup_auxv:
	# AT_NULL, 0
	xor	rax, rax
	call	spush
	call	spush

	# AT_RANDOM
	mov	rax, rsp
	call	spush
	mov	rax, 25
	call	spush

	# AT_SECURE
	xor	rax, rax
	call	spush
	mov	rax, 23
	call	spush

	# AT_PAGESZ
	mov	rax, 0x1000
	call	spush
	mov	rax, 6
	call	spush

	# AT_PHLEN
	mov	rbx, [rbp-8]
	mov	ax, [rbx+54]
	and	rax, 0xffff
	call	spush
	mov	rax, 4
	call	spush

	# AT_PHNUM
	mov	ax, [rbx+56]
	call	spush
	mov	rax, 5
	call	spush

	# AT_ENTRY
	mov	rax, [rbx+24]	# entry
	mov	rcx, [rbx+16]
	cmp	cl, 3		# ET_DYN
	jne	_setup_auxv_entry
	add	rax, rbx
_setup_auxv_entry:
	call	spush
	mov	rax, 9
	call	spush

	# AT_PHDR
	mov	rax, [rbx+32]	# phoff
	add	rax, rbx
	call	spush
	mov	rax, 3
	call	spush

	# AT_BASE
	mov	rax, [rbp-16]
	cmp	rax, 0
	je	_setup_auxv_end
	call	spush
	mov	rax, 7
	call	spush

_setup_auxv_end:
	ret


setup_stack:
	push	rbp
	mov	rbp, rsp
	sub	rsp, 64
	mov	[rbp-8], rax		# mmapped elf
	mov	[rbp-16], rbx		# mmapped interpreter
	mov	[rbp-24], rcx		# argv
	mov	[rbp-32], rdx		# envp


	xor	rdi, rdi
	mov	rsi, STACK_SIZE
	call	mmap
	add	rax, rsi
	mov	[rbp-40], rax		# stack (high mem)

	xor	rax, rax
	call	spush			# push 0
	mov	rax, 0x736c2f6e69622f	# /bin/ls
	call	spush
	call	spush
	mov	r15, [rbp-40]
	mov	rax, [rbp-40]
	and	rax, 0xfffffffffffffff0
	mov	[rbp-40], rax

	call	setup_auxv

	# envp
	xor	rax, rax
	call	spush

	# argv
	call	spush
	mov	rax, r15
	call	spush

	# argc
	xor	rax, rax
	inc	rax
	call	spush

	mov	rax, [rbp-40]
	leave
	ret

# -------------------------------------------------------------------- #
# rax = executable

# check if elf has interp
# open,read,close interp
# loadelf interp
# NOTE: we may be able to shortcut this if the interp is already loaded

loadinterp:
	push	rbp
	mov	rbp, rsp
	sub	rsp, 64
	mov	[rbp-8], rax

	call	getphdrs
	mov	[rbp-16], rsi	# phdrs base
	mov	[rbp-24], rcx	# phnum
	mov	[rbp-32], rdx	# phlen

	xor	rbx, rbx
_loadinterp:
	cmp	rbx, [rbp-24]
	je	_loadinterp_end

	mov	rsi, [rbp-16]
	mov	rax, [rbp-32]
	mul	rbx
	add	rsi, rax
	# PT_INTERP
	mov	eax, [rsi]
	cmp	eax, 3
	jne	_loadinterp_next

	mov	rdi, [rsi+8]	# offset
	add	rdi, [rbp-8]	# elf base
	xor	rsi, rsi	# O_RDONLY
	call	open
	mov	[rbp-40], rax	# fd

	mov	rdx, 409600	# 100 pages
	sub	rsp, rdx
	mov	rdi, rax
	mov	rsi, rsp
	call	read
	mov	rdi, [rbp-40]
	call	close
	mov	[rbp-40], rsp

	mov	rax, rsp
	call	loadelf
	leave
	ret

_loadinterp_next:
	inc	rbx
	jmp	_loadinterp

_loadinterp_end:
	xor	rax, rax
	leave
	ret

# -------------------------------------------------------------------- #
# Load an ELF into memory
#
# rax = loaded elf
#
# First, we calculate the loading address and required allocation size.
# Second, we copy the loadable sections into their respective locations
# and, finally, change their access protections according to the ELF.
#
# returns
# rax = elf base
#

loadelf:
	push	rbp
	mov	rbp, rsp
	sub	rsp, 64
	mov	[rbp-8], rax

	call	getphdrs
	mov	[rbp-16], rsi	# phdrs base
	mov	[rbp-24], rcx	# phnum
	mov	[rbp-32], rdx	# phlen
	xor	rax, rax
	mov	[rbp-40], rax	# size
	dec	rax
	mov	[rbp-48], rax	# base

	xor	rbx, rbx
_loadelf_prep:
	cmp	rbx, [rbp-24]
	je	_loadelf_prep_end

	mov	rsi, [rbp-16]
	mov	rax, [rbp-32]
	mul	rbx
	add	rsi, rax
	# PT_LOAD
	mov	eax, [rsi]
	cmp	eax, 1
	jne	_loadelf_prep_next

	# base
	mov	rax, [rsi+16]	# vaddr
	cmp	rax, [rbp-48]	# base
	ja	_loadelf_prep2
	mov	[rbp-48], rax

_loadelf_prep2:
	# size
	add	rax, [rsi+40]	# memsz
	cmp	rax, [rbp-40]
	jb	_loadelf_prep_next
	mov	[rbp-40], rax

_loadelf_prep_next:
	inc	rbx
	jmp	_loadelf_prep

_loadelf_prep_end:
	mov	rdi, [rbp-48]	# base
	mov	rsi, [rbp-40]	# size
	sub	rsi, rdi
	call	mmap
	cmp	rax, 0
	jl	exit
	mov	[rbp-56], rax	# elf mapping base

	xor	rbx, rbx
_loadelf_map:
	cmp	rbx, [rbp-24]
	je	_loadelf_end

	mov	rsi, [rbp-16]	# phdrs
	mov	rax, [rbp-32]	# phlen
	mul	rbx
	add	rsi, rax
	# PT_LOAD
	mov	eax, [rsi]
	cmp	eax, 1
	jne	_loadelf_map_next

	mov	rdx, rsi	# backup phdr base
	mov	rdi, [rbp-56]	# elf mapping base
	add	rdi, [rsi+16]	# vaddr
	sub	rdi, [rbp-48]	# loading base
	mov	rcx, [rsi+32]	# filesz
	mov	rsi, [rsi+8]	# offset
	add	rsi, [rbp-8]	# elf storage base
	call	memcpy

	and	rdi, 0xfffffffffffff000
	mov	rsi, [rdx+40]	# memsz
	mov	edx, [rdx+4]	# flags
	call	flags2prots
	call	mprotect

_loadelf_map_next:
	inc	rbx
	jmp	_loadelf_map

_loadelf_map_end:

_loadelf_end:
	mov	rax, [rbp-56]
	leave
	ret

# -------------------------------------------------------------------- #
# memcpy
# rdi = dst, rsi = src, rcx = cnt

memcpy:
	push	rax
	push	rsi
	push	rdi
	push	rcx
memcpy_:
	cmp	rcx, 0
	je	memcpy_end
	mov	al, [rsi]
	mov	[rdi], al
	dec	rcx
	inc	rdi
	inc	rsi
	jmp	memcpy_
memcpy_end:
	pop	rcx
	pop	rdi
	pop	rsi
	pop	rax
	ret

# -------------------------------------------------------------------- #
# rdx

flags2prots:
	push	rax
	push	rbx
	xor	rax, rax

	mov	rbx, rdx
	and	rbx, 1		# PF_X
	cmp	rbx, 0
	je	flags2prots_w
	or	rax, 4		# PROT_EXEC

flags2prots_w:
	mov	rbx, rdx
	and	rbx, 2		# PF_W
	cmp	rbx, 0
	je	flags2prots_r
	or	rax, 2		# PROT_WRITE

flags2prots_r:
	mov	rbx, rdx
	and	rbx, 4		# PF_R
	cmp	rbx, 0
	je	flags2prots_end
	or	rax, 1		# PROT_READ

flags2prots_end:
	mov	rdx, rax
	pop	rbx
	pop	rax
	ret

# -------------------------------------------------------------------- #
# rax = loaded elf
#
# returns
# rsi = base
# rcx = phnum
# rdx = phlen
#

getphdrs:
	xor	rcx, rcx
	xor	rdx, rdx

	mov	rsi, rax
	add	rsi, [rax+32]
	mov	cx, [rax+56]
	mov	dx, [rax+54]

	ret

# -------------------------------------------------------------------- #

mmap:
	mov	rax, 9		# sys_mmap
	mov	rdx, 3		# PROT_READ | PROT_WRITE
	mov	r10, 0x22	# MAP_ANONYMOUS | MAP_PRIVATE
	xor	r8, r8		# fd
	dec	r8
	xor	r9, r9		# offset
	syscall
	cmp	rax, -1
	je	fail
	ret

mprotect:
	mov	rax, 10		# sys_mprotect
	syscall
	cmp	rax, 0
	jne	fail
	ret

munmap:
	mov	rax, 11		# sys_munmap
	syscall
	cmp	rax, 0
	jne	fail
	ret

open:
	mov	rax, 2		# sys_open
	syscall
	cmp	rax, 0
	jl	fail
	ret

read:
	xor	rax, rax	# sys_read
	syscall
	cmp	rax, 0
	jl	fail
	cmp	rax, rdx
	je	fail
	ret

close:
	mov	rax, 3		# sys_close
	syscall
	ret

exit:
	mov	rax, 60		# sys_exit
	xor	rdi, rdi
	syscall

fail:
	mov	rax, 0x0a4c494146
	push	rax
	mov	rsi, rsp
	mov	rdi, 1
	mov	rax, 1
	mov	rdx, 5
	syscall
	jmp	exit
