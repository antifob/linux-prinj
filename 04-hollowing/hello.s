#
# This file is part of the linux-prinj project.
# https://gitlab.com/pgregoire/linux-prinj/
#
# Copyright 2022 Philippe Grégoire <git@pgregoire.xyz>
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
.text
.global _start

_start:
	# write(1, "Hello World!\n", 13);
	mov	rax, 0x0a21646c72
	push	rax
	mov	rax, 0x6f57206f6c6c6548
	push	rax
	mov	rdi, 1
	mov	rsi, rsp
	mov	rdx, 13
	mov	rax, 1
	syscall

	pop	rax
	pop	rax

	mov	rcx, 0x80000000
busywait:
	loop	busywait

	jmp	_start
