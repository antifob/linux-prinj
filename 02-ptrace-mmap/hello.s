
.intel_syntax noprefix
.text
.global _start

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
	push    rsp
	push    rbp
	push    rax
	push    rbx
	push    rcx
	push    rdx
	push    rdi
	push    rsi
	push    r8
	push    r9
	push    r10
	push    r11

        call    main

	# restore registries
	pop     r11
	pop     r10
	pop     r9
	pop     r8
	pop     rsi
	pop     rdi
	pop     rdx
	pop     rcx
	pop     rbx
	pop     rax
	pop     rbp
	pop     rsp

	jmp     jmpret

main:
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

	ret
