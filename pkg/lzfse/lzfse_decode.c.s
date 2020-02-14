	.section	__TEXT,__text,regular,pure_instructions
	.build_version macos, 10, 15	sdk_version 10, 15
	.intel_syntax noprefix
	.globl	_lzfse_decode_scratch_size ## -- Begin function lzfse_decode_scratch_size
	.p2align	4, 0x90
_lzfse_decode_scratch_size:             ## @lzfse_decode_scratch_size
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -8
	mov	eax, 47368
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function
	.private_extern	_lzfse_decode_buffer_with_scratch ## -- Begin function lzfse_decode_buffer_with_scratch
	.globl	_lzfse_decode_buffer_with_scratch
	.p2align	4, 0x90
_lzfse_decode_buffer_with_scratch:      ## @lzfse_decode_buffer_with_scratch
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -16
	sub	rsp, 80
	xor	eax, eax
	mov	r9, -1
	mov	qword ptr [rsp + 64], rdi
	mov	qword ptr [rsp + 56], rsi
	mov	qword ptr [rsp + 48], rdx
	mov	qword ptr [rsp + 40], rcx
	mov	qword ptr [rsp + 32], r8
	mov	rcx, qword ptr [rsp + 32]
	mov	qword ptr [rsp + 24], rcx
	mov	rcx, qword ptr [rsp + 24]
	mov	rdi, rcx
	mov	esi, eax
	mov	edx, 47368
	mov	rcx, r9
	call	___memset_chk
	mov	rcx, qword ptr [rsp + 48]
	mov	rdx, qword ptr [rsp + 24]
	mov	qword ptr [rdx], rcx
	mov	rcx, qword ptr [rsp + 48]
	mov	rdx, qword ptr [rsp + 24]
	mov	qword ptr [rdx + 8], rcx
	mov	rcx, qword ptr [rsp + 24]
	mov	rcx, qword ptr [rcx]
	add	rcx, qword ptr [rsp + 40]
	mov	rdx, qword ptr [rsp + 24]
	mov	qword ptr [rdx + 16], rcx
	mov	rcx, qword ptr [rsp + 64]
	mov	rdx, qword ptr [rsp + 24]
	mov	qword ptr [rdx + 24], rcx
	mov	rcx, qword ptr [rsp + 64]
	mov	rdx, qword ptr [rsp + 24]
	mov	qword ptr [rdx + 32], rcx
	mov	rcx, qword ptr [rsp + 64]
	add	rcx, qword ptr [rsp + 56]
	mov	rdx, qword ptr [rsp + 24]
	mov	qword ptr [rdx + 40], rcx
	mov	rdi, qword ptr [rsp + 24]
	mov	qword ptr [rsp + 8], rax ## 8-byte Spill
	call	_lzfse_decode
	mov	dword ptr [rsp + 20], eax
	cmp	dword ptr [rsp + 20], -2
	jne	LBB1_2
## %bb.1:
	mov	rax, qword ptr [rsp + 56]
	mov	qword ptr [rsp + 72], rax
	jmp	LBB1_5
LBB1_2:
	cmp	dword ptr [rsp + 20], 0
	je	LBB1_4
## %bb.3:
	mov	qword ptr [rsp + 72], 0
	jmp	LBB1_5
LBB1_4:
	mov	rax, qword ptr [rsp + 24]
	mov	rax, qword ptr [rax + 24]
	mov	rcx, qword ptr [rsp + 64]
	sub	rax, rcx
	mov	qword ptr [rsp + 72], rax
LBB1_5:
	mov	rax, qword ptr [rsp + 72]
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function
	.globl	_lzfse_decode_buffer    ## -- Begin function lzfse_decode_buffer
	.p2align	4, 0x90
_lzfse_decode_buffer:                   ## @lzfse_decode_buffer
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -16
	sub	rsp, 64
	mov	qword ptr [rsp + 48], rdi
	mov	qword ptr [rsp + 40], rsi
	mov	qword ptr [rsp + 32], rdx
	mov	qword ptr [rsp + 24], rcx
	mov	qword ptr [rsp + 16], r8
	mov	dword ptr [rsp + 12], 0
	mov	qword ptr [rsp], 0
	cmp	qword ptr [rsp + 16], 0
	jne	LBB2_2
## %bb.1:
	call	_lzfse_decode_scratch_size
	add	rax, 1
	mov	rdi, rax
	call	_malloc
	mov	qword ptr [rsp + 16], rax
	mov	dword ptr [rsp + 12], 1
LBB2_2:
	cmp	qword ptr [rsp + 16], 0
	jne	LBB2_4
## %bb.3:
	mov	qword ptr [rsp + 56], 0
	jmp	LBB2_7
LBB2_4:
	mov	rdi, qword ptr [rsp + 48]
	mov	rsi, qword ptr [rsp + 40]
	mov	rdx, qword ptr [rsp + 32]
	mov	rcx, qword ptr [rsp + 24]
	mov	r8, qword ptr [rsp + 16]
	call	_lzfse_decode_buffer_with_scratch
	mov	qword ptr [rsp], rax
	cmp	dword ptr [rsp + 12], 0
	je	LBB2_6
## %bb.5:
	mov	rdi, qword ptr [rsp + 16]
	call	_free
LBB2_6:
	mov	rax, qword ptr [rsp]
	mov	qword ptr [rsp + 56], rax
LBB2_7:
	mov	rax, qword ptr [rsp + 56]
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function

.subsections_via_symbols
