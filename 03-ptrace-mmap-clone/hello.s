
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
	push	r12
	push	r13
	push	r14
	push	r15

        call    main

	# restore registries
	pop	r15
	pop	r14
	pop	r13
	pop	r12
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
	# Setup a stack for the thread.
        mov     rax, 9		# sys_mmap
        mov     rdi, 0		# base address (0=anywhere)
        mov     rsi, 8192       # len
        mov     rdx, 3          # PROT_READ | PROT_WRITE
        mov     r10, 0x22       # MAP_ANONYMOUS | MAP_PRIVATE
        xor     r8, r8		# -1
        dec     r8
        xor     r9, r9		# 0
        syscall

	# Start the thread
        mov     rsi, rax
        add     rsi, 0x1000	# top of the stack
        mov     rax, 56		# sys_clone
        mov     rdi, 0x10900    # CLONE_VM | CLONE_THREAD | CLONE_SIGHAND
        xor     rdx, rdx
        xor     r10, r10
        xor     r9, r9
        syscall

        cmp     rax, 0
        je      child
	ret

child:
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

	jmp	child
