	.section	__TEXT,__text,regular,pure_instructions
	.build_version macos, 10, 15	sdk_version 10, 15
	.intel_syntax noprefix
	.globl	_fse_init_encoder_table ## -- Begin function fse_init_encoder_table
	.p2align	4, 0x90
_fse_init_encoder_table:                ## @fse_init_encoder_table
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -8
	sub	rsp, 48
	mov	dword ptr [rsp + 44], edi
	mov	dword ptr [rsp + 40], esi
	mov	qword ptr [rsp + 32], rdx
	mov	qword ptr [rsp + 24], rcx
	mov	dword ptr [rsp + 20], 0
	mov	esi, dword ptr [rsp + 44]
	bsr	esi, esi
	xor	esi, 31
	mov	dword ptr [rsp + 16], esi
	mov	dword ptr [rsp + 12], 0
LBB0_1:                                 ## =>This Inner Loop Header: Depth=1
	mov	eax, dword ptr [rsp + 12]
	cmp	eax, dword ptr [rsp + 40]
	jge	LBB0_6
## %bb.2:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 32]
	movsxd	rcx, dword ptr [rsp + 12]
	movzx	edx, word ptr [rax + 2*rcx]
	mov	dword ptr [rsp + 8], edx
	cmp	dword ptr [rsp + 8], 0
	jne	LBB0_4
## %bb.3:                               ##   in Loop: Header=BB0_1 Depth=1
	jmp	LBB0_5
LBB0_4:                                 ##   in Loop: Header=BB0_1 Depth=1
	mov	eax, dword ptr [rsp + 8]
	bsr	eax, eax
	xor	eax, 31
	sub	eax, dword ptr [rsp + 16]
	mov	dword ptr [rsp + 4], eax
	mov	eax, dword ptr [rsp + 8]
	mov	ecx, dword ptr [rsp + 4]
                                        ## kill: def $cl killed $ecx
	shl	eax, cl
	sub	eax, dword ptr [rsp + 44]
	mov	dx, ax
	mov	rsi, qword ptr [rsp + 24]
	movsxd	rdi, dword ptr [rsp + 12]
	mov	word ptr [rsi + 8*rdi], dx
	mov	eax, dword ptr [rsp + 4]
	mov	dx, ax
	mov	rsi, qword ptr [rsp + 24]
	movsxd	rdi, dword ptr [rsp + 12]
	mov	word ptr [rsi + 8*rdi + 2], dx
	mov	eax, dword ptr [rsp + 20]
	sub	eax, dword ptr [rsp + 8]
	mov	r8d, dword ptr [rsp + 44]
	mov	ecx, dword ptr [rsp + 4]
                                        ## kill: def $cl killed $ecx
	sar	r8d, cl
	add	eax, r8d
	mov	dx, ax
	mov	rsi, qword ptr [rsp + 24]
	movsxd	rdi, dword ptr [rsp + 12]
	mov	word ptr [rsi + 8*rdi + 4], dx
	mov	eax, dword ptr [rsp + 20]
	sub	eax, dword ptr [rsp + 8]
	mov	r8d, dword ptr [rsp + 44]
	mov	r9d, dword ptr [rsp + 4]
	sub	r9d, 1
	mov	ecx, r9d
                                        ## kill: def $cl killed $ecx
	sar	r8d, cl
	add	eax, r8d
	mov	dx, ax
	mov	rsi, qword ptr [rsp + 24]
	movsxd	rdi, dword ptr [rsp + 12]
	mov	word ptr [rsi + 8*rdi + 6], dx
	mov	eax, dword ptr [rsp + 8]
	add	eax, dword ptr [rsp + 20]
	mov	dword ptr [rsp + 20], eax
LBB0_5:                                 ##   in Loop: Header=BB0_1 Depth=1
	mov	eax, dword ptr [rsp + 12]
	add	eax, 1
	mov	dword ptr [rsp + 12], eax
	jmp	LBB0_1
LBB0_6:
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function
	.globl	_fse_init_decoder_table ## -- Begin function fse_init_decoder_table
	.p2align	4, 0x90
_fse_init_decoder_table:                ## @fse_init_decoder_table
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -16
	sub	rsp, 112
	mov	dword ptr [rsp + 68], edi
	mov	dword ptr [rsp + 64], esi
	mov	qword ptr [rsp + 56], rdx
	mov	qword ptr [rsp + 48], rcx
	cmp	dword ptr [rsp + 64], 256
	setle	al
	xor	al, -1
	and	al, 1
	movzx	esi, al
	movsxd	rcx, esi
	cmp	rcx, 0
	je	LBB1_2
## %bb.1:
	lea	rdi, [rip + L___func__.fse_init_decoder_table]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 60
	call	___assert_rtn
LBB1_2:
	jmp	LBB1_3
LBB1_3:
	mov	rax, qword ptr [rsp + 56]
	movsxd	rcx, dword ptr [rsp + 64]
	movsxd	rdx, dword ptr [rsp + 68]
	mov	qword ptr [rsp + 104], rax
	mov	qword ptr [rsp + 96], rcx
	mov	qword ptr [rsp + 88], rdx
	mov	qword ptr [rsp + 80], 0
	mov	dword ptr [rsp + 76], 0
LBB1_4:                                 ## =>This Inner Loop Header: Depth=1
	movsxd	rax, dword ptr [rsp + 76]
	cmp	rax, qword ptr [rsp + 96]
	jae	LBB1_6
## %bb.5:                               ##   in Loop: Header=BB1_4 Depth=1
	mov	rax, qword ptr [rsp + 104]
	movsxd	rcx, dword ptr [rsp + 76]
	movzx	edx, word ptr [rax + 2*rcx]
	mov	eax, edx
	add	rax, qword ptr [rsp + 80]
	mov	qword ptr [rsp + 80], rax
	mov	edx, dword ptr [rsp + 76]
	add	edx, 1
	mov	dword ptr [rsp + 76], edx
	jmp	LBB1_4
LBB1_6:
	xor	eax, eax
	mov	rcx, qword ptr [rsp + 80]
	mov	rdx, qword ptr [rsp + 88]
	cmp	rcx, rdx
	mov	esi, 4294967295
	cmova	eax, esi
	cmp	eax, 0
	sete	dil
	xor	dil, -1
	and	dil, 1
	movzx	eax, dil
	movsxd	rcx, eax
	cmp	rcx, 0
	je	LBB1_8
## %bb.7:
	lea	rdi, [rip + L___func__.fse_init_decoder_table]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 61
	call	___assert_rtn
LBB1_8:
	jmp	LBB1_9
LBB1_9:
	mov	eax, dword ptr [rsp + 68]
	bsr	eax, eax
	xor	eax, 31
	mov	dword ptr [rsp + 44], eax
	mov	dword ptr [rsp + 40], 0
	mov	dword ptr [rsp + 36], 0
LBB1_10:                                ## =>This Loop Header: Depth=1
                                        ##     Child Loop BB1_16 Depth 2
	mov	eax, dword ptr [rsp + 36]
	cmp	eax, dword ptr [rsp + 64]
	jge	LBB1_24
## %bb.11:                              ##   in Loop: Header=BB1_10 Depth=1
	mov	rax, qword ptr [rsp + 56]
	movsxd	rcx, dword ptr [rsp + 36]
	movzx	edx, word ptr [rax + 2*rcx]
	mov	dword ptr [rsp + 32], edx
	cmp	dword ptr [rsp + 32], 0
	jne	LBB1_13
## %bb.12:                              ##   in Loop: Header=BB1_10 Depth=1
	jmp	LBB1_23
LBB1_13:                                ##   in Loop: Header=BB1_10 Depth=1
	mov	eax, dword ptr [rsp + 32]
	add	eax, dword ptr [rsp + 40]
	mov	dword ptr [rsp + 40], eax
	mov	eax, dword ptr [rsp + 40]
	cmp	eax, dword ptr [rsp + 68]
	jle	LBB1_15
## %bb.14:
	mov	dword ptr [rsp + 72], -1
	jmp	LBB1_25
LBB1_15:                                ##   in Loop: Header=BB1_10 Depth=1
	mov	eax, dword ptr [rsp + 32]
	bsr	eax, eax
	xor	eax, 31
	sub	eax, dword ptr [rsp + 44]
	mov	dword ptr [rsp + 28], eax
	mov	eax, dword ptr [rsp + 68]
	shl	eax, 1
	mov	ecx, dword ptr [rsp + 28]
                                        ## kill: def $cl killed $ecx
	sar	eax, cl
	sub	eax, dword ptr [rsp + 32]
	mov	dword ptr [rsp + 24], eax
	mov	dword ptr [rsp + 20], 0
LBB1_16:                                ##   Parent Loop BB1_10 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	mov	eax, dword ptr [rsp + 20]
	cmp	eax, dword ptr [rsp + 32]
	jge	LBB1_22
## %bb.17:                              ##   in Loop: Header=BB1_16 Depth=2
	mov	eax, dword ptr [rsp + 36]
	mov	cl, al
	mov	byte ptr [rsp + 17], cl
	mov	eax, dword ptr [rsp + 20]
	cmp	eax, dword ptr [rsp + 24]
	jge	LBB1_19
## %bb.18:                              ##   in Loop: Header=BB1_16 Depth=2
	mov	eax, dword ptr [rsp + 28]
	mov	cl, al
	mov	byte ptr [rsp + 16], cl
	mov	eax, dword ptr [rsp + 32]
	add	eax, dword ptr [rsp + 20]
	mov	ecx, dword ptr [rsp + 28]
                                        ## kill: def $cl killed $ecx
	shl	eax, cl
	sub	eax, dword ptr [rsp + 68]
	mov	dx, ax
	mov	word ptr [rsp + 18], dx
	jmp	LBB1_20
LBB1_19:                                ##   in Loop: Header=BB1_16 Depth=2
	mov	eax, dword ptr [rsp + 28]
	sub	eax, 1
	mov	cl, al
	mov	byte ptr [rsp + 16], cl
	mov	eax, dword ptr [rsp + 20]
	sub	eax, dword ptr [rsp + 24]
	mov	edx, dword ptr [rsp + 28]
	sub	edx, 1
	mov	ecx, edx
                                        ## kill: def $cl killed $ecx
	shl	eax, cl
	mov	si, ax
	mov	word ptr [rsp + 18], si
LBB1_20:                                ##   in Loop: Header=BB1_16 Depth=2
	mov	rcx, -1
	mov	rax, qword ptr [rsp + 48]
	lea	rdx, [rsp + 16]
	mov	rdi, rax
	mov	rsi, rdx
	mov	edx, 4
	call	___memcpy_chk
	mov	rcx, qword ptr [rsp + 48]
	add	rcx, 4
	mov	qword ptr [rsp + 48], rcx
	mov	qword ptr [rsp + 8], rax ## 8-byte Spill
## %bb.21:                              ##   in Loop: Header=BB1_16 Depth=2
	mov	eax, dword ptr [rsp + 20]
	add	eax, 1
	mov	dword ptr [rsp + 20], eax
	jmp	LBB1_16
LBB1_22:                                ##   in Loop: Header=BB1_10 Depth=1
	jmp	LBB1_23
LBB1_23:                                ##   in Loop: Header=BB1_10 Depth=1
	mov	eax, dword ptr [rsp + 36]
	add	eax, 1
	mov	dword ptr [rsp + 36], eax
	jmp	LBB1_10
LBB1_24:
	mov	dword ptr [rsp + 72], 0
LBB1_25:
	mov	eax, dword ptr [rsp + 72]
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function
	.globl	_fse_init_value_decoder_table ## -- Begin function fse_init_value_decoder_table
	.p2align	4, 0x90
_fse_init_value_decoder_table:          ## @fse_init_value_decoder_table
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -16
	sub	rsp, 144
	mov	dword ptr [rsp + 104], edi
	mov	dword ptr [rsp + 100], esi
	mov	qword ptr [rsp + 88], rdx
	mov	qword ptr [rsp + 80], rcx
	mov	qword ptr [rsp + 72], r8
	mov	qword ptr [rsp + 64], r9
	cmp	dword ptr [rsp + 100], 256
	setle	al
	xor	al, -1
	and	al, 1
	movzx	esi, al
	movsxd	rcx, esi
	cmp	rcx, 0
	je	LBB2_2
## %bb.1:
	lea	rdi, [rip + L___func__.fse_init_value_decoder_table]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 114
	call	___assert_rtn
LBB2_2:
	jmp	LBB2_3
LBB2_3:
	mov	rax, qword ptr [rsp + 88]
	movsxd	rcx, dword ptr [rsp + 100]
	movsxd	rdx, dword ptr [rsp + 104]
	mov	qword ptr [rsp + 136], rax
	mov	qword ptr [rsp + 128], rcx
	mov	qword ptr [rsp + 120], rdx
	mov	qword ptr [rsp + 112], 0
	mov	dword ptr [rsp + 108], 0
LBB2_4:                                 ## =>This Inner Loop Header: Depth=1
	movsxd	rax, dword ptr [rsp + 108]
	cmp	rax, qword ptr [rsp + 128]
	jae	LBB2_6
## %bb.5:                               ##   in Loop: Header=BB2_4 Depth=1
	mov	rax, qword ptr [rsp + 136]
	movsxd	rcx, dword ptr [rsp + 108]
	movzx	edx, word ptr [rax + 2*rcx]
	mov	eax, edx
	add	rax, qword ptr [rsp + 112]
	mov	qword ptr [rsp + 112], rax
	mov	edx, dword ptr [rsp + 108]
	add	edx, 1
	mov	dword ptr [rsp + 108], edx
	jmp	LBB2_4
LBB2_6:
	xor	eax, eax
	mov	rcx, qword ptr [rsp + 112]
	mov	rdx, qword ptr [rsp + 120]
	cmp	rcx, rdx
	mov	esi, 4294967295
	cmova	eax, esi
	cmp	eax, 0
	sete	dil
	xor	dil, -1
	and	dil, 1
	movzx	eax, dil
	movsxd	rcx, eax
	cmp	rcx, 0
	je	LBB2_8
## %bb.7:
	lea	rdi, [rip + L___func__.fse_init_value_decoder_table]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 115
	call	___assert_rtn
LBB2_8:
	jmp	LBB2_9
LBB2_9:
	mov	eax, dword ptr [rsp + 104]
	bsr	eax, eax
	xor	eax, 31
	mov	dword ptr [rsp + 60], eax
	mov	dword ptr [rsp + 56], 0
LBB2_10:                                ## =>This Loop Header: Depth=1
                                        ##     Child Loop BB2_14 Depth 2
	mov	eax, dword ptr [rsp + 56]
	cmp	eax, dword ptr [rsp + 100]
	jge	LBB2_22
## %bb.11:                              ##   in Loop: Header=BB2_10 Depth=1
	mov	rax, qword ptr [rsp + 88]
	movsxd	rcx, dword ptr [rsp + 56]
	movzx	edx, word ptr [rax + 2*rcx]
	mov	dword ptr [rsp + 52], edx
	cmp	dword ptr [rsp + 52], 0
	jne	LBB2_13
## %bb.12:                              ##   in Loop: Header=BB2_10 Depth=1
	jmp	LBB2_21
LBB2_13:                                ##   in Loop: Header=BB2_10 Depth=1
	xor	esi, esi
	mov	eax, dword ptr [rsp + 52]
	bsr	eax, eax
	xor	eax, 31
	sub	eax, dword ptr [rsp + 60]
	mov	dword ptr [rsp + 48], eax
	mov	eax, dword ptr [rsp + 104]
	shl	eax, 1
	mov	ecx, dword ptr [rsp + 48]
                                        ## kill: def $cl killed $ecx
	sar	eax, cl
	sub	eax, dword ptr [rsp + 52]
	mov	dword ptr [rsp + 44], eax
	lea	rdx, [rsp + 32]
	mov	rdi, rdx
	mov	edx, 8
	call	_memset
	mov	rdx, qword ptr [rsp + 80]
	movsxd	rdi, dword ptr [rsp + 56]
	mov	cl, byte ptr [rdx + rdi]
	mov	byte ptr [rsp + 33], cl
	mov	rdx, qword ptr [rsp + 72]
	movsxd	rdi, dword ptr [rsp + 56]
	mov	eax, dword ptr [rdx + 4*rdi]
	mov	dword ptr [rsp + 36], eax
	mov	dword ptr [rsp + 28], 0
LBB2_14:                                ##   Parent Loop BB2_10 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	mov	eax, dword ptr [rsp + 28]
	cmp	eax, dword ptr [rsp + 52]
	jge	LBB2_20
## %bb.15:                              ##   in Loop: Header=BB2_14 Depth=2
	mov	rax, qword ptr [rsp + 32]
	mov	qword ptr [rsp + 16], rax
	mov	ecx, dword ptr [rsp + 28]
	cmp	ecx, dword ptr [rsp + 44]
	jge	LBB2_17
## %bb.16:                              ##   in Loop: Header=BB2_14 Depth=2
	mov	eax, dword ptr [rsp + 48]
	mov	cl, al
	movzx	eax, cl
	movzx	edx, byte ptr [rsp + 17]
	add	eax, edx
	mov	cl, al
	mov	byte ptr [rsp + 16], cl
	mov	eax, dword ptr [rsp + 52]
	add	eax, dword ptr [rsp + 28]
	mov	ecx, dword ptr [rsp + 48]
                                        ## kill: def $cl killed $ecx
	shl	eax, cl
	sub	eax, dword ptr [rsp + 104]
	mov	si, ax
	mov	word ptr [rsp + 18], si
	jmp	LBB2_18
LBB2_17:                                ##   in Loop: Header=BB2_14 Depth=2
	mov	eax, dword ptr [rsp + 48]
	sub	eax, 1
	mov	cl, al
	movzx	eax, cl
	movzx	edx, byte ptr [rsp + 17]
	add	eax, edx
	mov	cl, al
	mov	byte ptr [rsp + 16], cl
	mov	eax, dword ptr [rsp + 28]
	sub	eax, dword ptr [rsp + 44]
	mov	edx, dword ptr [rsp + 48]
	sub	edx, 1
	mov	ecx, edx
                                        ## kill: def $cl killed $ecx
	shl	eax, cl
	mov	si, ax
	mov	word ptr [rsp + 18], si
LBB2_18:                                ##   in Loop: Header=BB2_14 Depth=2
	mov	rcx, -1
	mov	rax, qword ptr [rsp + 64]
	lea	rdx, [rsp + 16]
	mov	rdi, rax
	mov	rsi, rdx
	mov	edx, 8
	call	___memcpy_chk
	mov	rcx, qword ptr [rsp + 64]
	add	rcx, 8
	mov	qword ptr [rsp + 64], rcx
	mov	qword ptr [rsp + 8], rax ## 8-byte Spill
## %bb.19:                              ##   in Loop: Header=BB2_14 Depth=2
	mov	eax, dword ptr [rsp + 28]
	add	eax, 1
	mov	dword ptr [rsp + 28], eax
	jmp	LBB2_14
LBB2_20:                                ##   in Loop: Header=BB2_10 Depth=1
	jmp	LBB2_21
LBB2_21:                                ##   in Loop: Header=BB2_10 Depth=1
	mov	eax, dword ptr [rsp + 56]
	add	eax, 1
	mov	dword ptr [rsp + 56], eax
	jmp	LBB2_10
LBB2_22:
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function
	.globl	_fse_normalize_freq     ## -- Begin function fse_normalize_freq
	.p2align	4, 0x90
_fse_normalize_freq:                    ## @fse_normalize_freq
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -16
	sub	rsp, 64
	mov	dword ptr [rsp + 60], edi
	mov	dword ptr [rsp + 56], esi
	mov	qword ptr [rsp + 48], rdx
	mov	qword ptr [rsp + 40], rcx
	mov	dword ptr [rsp + 36], 0
	mov	esi, dword ptr [rsp + 60]
	mov	dword ptr [rsp + 32], esi
	mov	dword ptr [rsp + 28], 0
	mov	dword ptr [rsp + 24], 0
	mov	esi, dword ptr [rsp + 60]
	bsr	esi, esi
	xor	esi, 31
	sub	esi, 1
	mov	dword ptr [rsp + 20], esi
	mov	dword ptr [rsp + 12], 0
LBB3_1:                                 ## =>This Inner Loop Header: Depth=1
	mov	eax, dword ptr [rsp + 12]
	cmp	eax, dword ptr [rsp + 56]
	jge	LBB3_4
## %bb.2:                               ##   in Loop: Header=BB3_1 Depth=1
	mov	rax, qword ptr [rsp + 48]
	movsxd	rcx, dword ptr [rsp + 12]
	mov	edx, dword ptr [rax + 4*rcx]
	add	edx, dword ptr [rsp + 36]
	mov	dword ptr [rsp + 36], edx
## %bb.3:                               ##   in Loop: Header=BB3_1 Depth=1
	mov	eax, dword ptr [rsp + 12]
	add	eax, 1
	mov	dword ptr [rsp + 12], eax
	jmp	LBB3_1
LBB3_4:
	cmp	dword ptr [rsp + 36], 0
	jne	LBB3_6
## %bb.5:
	mov	dword ptr [rsp + 16], 0
	jmp	LBB3_7
LBB3_6:
	mov	eax, 2147483648
	xor	edx, edx
	div	dword ptr [rsp + 36]
	mov	dword ptr [rsp + 16], eax
LBB3_7:
	mov	dword ptr [rsp + 8], 0
LBB3_8:                                 ## =>This Inner Loop Header: Depth=1
	mov	eax, dword ptr [rsp + 8]
	cmp	eax, dword ptr [rsp + 56]
	jge	LBB3_16
## %bb.9:                               ##   in Loop: Header=BB3_8 Depth=1
	mov	rax, qword ptr [rsp + 48]
	movsxd	rcx, dword ptr [rsp + 8]
	mov	edx, dword ptr [rax + 4*rcx]
	imul	edx, dword ptr [rsp + 16]
	mov	ecx, dword ptr [rsp + 20]
                                        ## kill: def $cl killed $ecx
	shr	edx, cl
	add	edx, 1
	shr	edx, 1
	mov	dword ptr [rsp + 4], edx
	cmp	dword ptr [rsp + 4], 0
	jne	LBB3_12
## %bb.10:                              ##   in Loop: Header=BB3_8 Depth=1
	mov	rax, qword ptr [rsp + 48]
	movsxd	rcx, dword ptr [rsp + 8]
	cmp	dword ptr [rax + 4*rcx], 0
	je	LBB3_12
## %bb.11:                              ##   in Loop: Header=BB3_8 Depth=1
	mov	dword ptr [rsp + 4], 1
LBB3_12:                                ##   in Loop: Header=BB3_8 Depth=1
	mov	eax, dword ptr [rsp + 4]
	mov	cx, ax
	mov	rdx, qword ptr [rsp + 40]
	movsxd	rsi, dword ptr [rsp + 8]
	mov	word ptr [rdx + 2*rsi], cx
	mov	eax, dword ptr [rsp + 4]
	mov	edi, dword ptr [rsp + 32]
	sub	edi, eax
	mov	dword ptr [rsp + 32], edi
	mov	eax, dword ptr [rsp + 4]
	cmp	eax, dword ptr [rsp + 28]
	jle	LBB3_14
## %bb.13:                              ##   in Loop: Header=BB3_8 Depth=1
	mov	eax, dword ptr [rsp + 4]
	mov	dword ptr [rsp + 28], eax
	mov	eax, dword ptr [rsp + 8]
	mov	dword ptr [rsp + 24], eax
LBB3_14:                                ##   in Loop: Header=BB3_8 Depth=1
	jmp	LBB3_15
LBB3_15:                                ##   in Loop: Header=BB3_8 Depth=1
	mov	eax, dword ptr [rsp + 8]
	add	eax, 1
	mov	dword ptr [rsp + 8], eax
	jmp	LBB3_8
LBB3_16:
	xor	eax, eax
	sub	eax, dword ptr [rsp + 32]
	mov	ecx, dword ptr [rsp + 28]
	sar	ecx, 2
	cmp	eax, ecx
	jge	LBB3_18
## %bb.17:
	mov	eax, dword ptr [rsp + 32]
	mov	rcx, qword ptr [rsp + 40]
	movsxd	rdx, dword ptr [rsp + 24]
	movzx	esi, word ptr [rcx + 2*rdx]
	add	esi, eax
	mov	di, si
	mov	word ptr [rcx + 2*rdx], di
	jmp	LBB3_19
LBB3_18:
	xor	eax, eax
	mov	rdi, qword ptr [rsp + 40]
	sub	eax, dword ptr [rsp + 32]
	mov	edx, dword ptr [rsp + 56]
	mov	esi, eax
	call	_fse_adjust_freqs
LBB3_19:
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function fse_adjust_freqs
_fse_adjust_freqs:                      ## @fse_adjust_freqs
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -8
	sub	rsp, 32
	mov	qword ptr [rsp + 24], rdi
	mov	dword ptr [rsp + 20], esi
	mov	dword ptr [rsp + 16], edx
	mov	dword ptr [rsp + 12], 3
LBB4_1:                                 ## =>This Loop Header: Depth=1
                                        ##     Child Loop BB4_3 Depth 2
	cmp	dword ptr [rsp + 20], 0
	je	LBB4_14
## %bb.2:                               ##   in Loop: Header=BB4_1 Depth=1
	mov	dword ptr [rsp + 8], 0
LBB4_3:                                 ##   Parent Loop BB4_1 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	mov	eax, dword ptr [rsp + 8]
	cmp	eax, dword ptr [rsp + 16]
	jge	LBB4_12
## %bb.4:                               ##   in Loop: Header=BB4_3 Depth=2
	mov	rax, qword ptr [rsp + 24]
	movsxd	rcx, dword ptr [rsp + 8]
	movzx	edx, word ptr [rax + 2*rcx]
	cmp	edx, 1
	jle	LBB4_10
## %bb.5:                               ##   in Loop: Header=BB4_3 Depth=2
	mov	rax, qword ptr [rsp + 24]
	movsxd	rcx, dword ptr [rsp + 8]
	movzx	edx, word ptr [rax + 2*rcx]
	sub	edx, 1
	mov	ecx, dword ptr [rsp + 12]
                                        ## kill: def $cl killed $ecx
	sar	edx, cl
	mov	dword ptr [rsp + 4], edx
	mov	edx, dword ptr [rsp + 4]
	cmp	edx, dword ptr [rsp + 20]
	jle	LBB4_7
## %bb.6:                               ##   in Loop: Header=BB4_3 Depth=2
	mov	eax, dword ptr [rsp + 20]
	mov	dword ptr [rsp + 4], eax
LBB4_7:                                 ##   in Loop: Header=BB4_3 Depth=2
	mov	eax, dword ptr [rsp + 4]
	mov	rcx, qword ptr [rsp + 24]
	movsxd	rdx, dword ptr [rsp + 8]
	movzx	esi, word ptr [rcx + 2*rdx]
	sub	esi, eax
	mov	di, si
	mov	word ptr [rcx + 2*rdx], di
	mov	eax, dword ptr [rsp + 4]
	mov	esi, dword ptr [rsp + 20]
	sub	esi, eax
	mov	dword ptr [rsp + 20], esi
	cmp	dword ptr [rsp + 20], 0
	jne	LBB4_9
## %bb.8:                               ##   in Loop: Header=BB4_1 Depth=1
	jmp	LBB4_12
LBB4_9:                                 ##   in Loop: Header=BB4_3 Depth=2
	jmp	LBB4_10
LBB4_10:                                ##   in Loop: Header=BB4_3 Depth=2
	jmp	LBB4_11
LBB4_11:                                ##   in Loop: Header=BB4_3 Depth=2
	mov	eax, dword ptr [rsp + 8]
	add	eax, 1
	mov	dword ptr [rsp + 8], eax
	jmp	LBB4_3
LBB4_12:                                ##   in Loop: Header=BB4_1 Depth=1
	jmp	LBB4_13
LBB4_13:                                ##   in Loop: Header=BB4_1 Depth=1
	mov	eax, dword ptr [rsp + 12]
	add	eax, -1
	mov	dword ptr [rsp + 12], eax
	jmp	LBB4_1
LBB4_14:
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function
	.section	__TEXT,__cstring,cstring_literals
L___func__.fse_init_decoder_table:      ## @__func__.fse_init_decoder_table
	.asciz	"fse_init_decoder_table"

L_.str:                                 ## @.str
	.asciz	"/Users/blacktop/Downloads/lzfse-master/src/lzfse_fse.c"

L_.str.1:                               ## @.str.1
	.asciz	"nsymbols <= 256"

L_.str.2:                               ## @.str.2
	.asciz	"fse_check_freq(freq, nsymbols, nstates) == 0"

L___func__.fse_init_value_decoder_table: ## @__func__.fse_init_value_decoder_table
	.asciz	"fse_init_value_decoder_table"


.subsections_via_symbols
