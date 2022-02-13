
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
