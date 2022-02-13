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

.intel_syntax noprefix
.global _start
.text

_start:
	# debugging
	#jmp	_start
	nop; nop

	jmp	entry
jmpret:
	# The target return address is stored right before this
	# shellcode. Use it as the jmp target.
	# Subtract 2 if the nops above are removed.
	jmp	[rip-10-8]

entry:
	# backup registries
	push	rsp
	push	rbp
	push	rax
	push	rbx
	push	rcx
	push	rdx
	push	rdi
	push	rsi
	push	r8
	push	r9
	push	r10
	push	r11
	push	r12
	push	r13
	push	r14
	push	r15

	call	hook

	# restore registries
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rsi
	pop	rdi
	pop	rdx
	pop	rcx
	pop	rbx
	pop	rax
	pop	rbp
	pop	rsp

	jmp	jmpret

hook:
	jmp	end
hook2:
	pop	rbp
	mov	rbx, rbp
	add	rbp, 9

	# sigaction
	push	0			# sa_mask
	push	0
	push	0
	push	0
	push	0
	push	0
	push	0
	push	0
	push	0
	push	0
	push	0
	push	0
	push	0
	push	0
	push	0
	push	0
	push	rbx			# sa_restorer
	push	0x04000000		# sa_flags SA_RESTORER
	push	rbp			# sa_handler

	mov	rax, 13
	mov	rdi, 34			# SIGRTMIN
	mov	rsi, rsp
	mov	rdx, 0
	mov	r10, 8			# varies between systems
        syscall
	add	rsp, (19*8)

	# timer_create
	push	0
	push	0
	push	0
	push	0
	push	34			# sigev_signo
	push	0			# sigev_notify SIGEV_SIGNAL
	mov	rax, 222		# sys_timer_create
	mov	rdi, 1			# CLOCK_MONOTONIC
	mov	rsi, rsp		# sigev
	sub	rsp, 8
	mov	rdx, rsp
	syscall
	pop	rdi			# timerid
	add	rsp, (6*8)

	# timer_settime
	push	2
	push	2
	push	2
	push	2
	mov	rax, 223		# sys_timer_settime
	mov	rsi, 0
	mov	rdx, rsp		# tspec
	mov	r10, 0			# old
	syscall
	add	rsp, (4*8)

	ret

end:
	call	hook2

sa_restore:
	# sigreturn
	mov	rax, 15
	syscall

child:
	# write(1, "Hello World!\n", 13);
	mov     rax, 0x0a21646c72
	push    rax
	mov     rax, 0x6f57206f6c6c6548
	push    rax
	mov     rdi, 1
	mov     rsi, rsp
	mov     rdx, 13
	mov     rax, 1
	syscall

	pop     rax
	pop     rax
	ret
