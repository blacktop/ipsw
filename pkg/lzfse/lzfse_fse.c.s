	.section	__TEXT,__text,regular,pure_instructions
	.build_version macos, 10, 15	sdk_version 10, 15
	.private_extern	_fse_init_encoder_table ## -- Begin function fse_init_encoder_table
	.globl	_fse_init_encoder_table
	.p2align	4, 0x90
_fse_init_encoder_table:                ## @fse_init_encoder_table
	.cfi_startproc
## %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movl	%edi, -4(%rbp)
	movl	%esi, -8(%rbp)
	movq	%rdx, -16(%rbp)
	movq	%rcx, -24(%rbp)
	movl	$0, -28(%rbp)
	movl	-4(%rbp), %esi
	bsrl	%esi, %esi
	xorl	$31, %esi
	movl	%esi, -32(%rbp)
	movl	$0, -36(%rbp)
LBB0_1:                                 ## =>This Inner Loop Header: Depth=1
	movl	-36(%rbp), %eax
	cmpl	-8(%rbp), %eax
	jge	LBB0_6
## %bb.2:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-16(%rbp), %rax
	movslq	-36(%rbp), %rcx
	movzwl	(%rax,%rcx,2), %edx
	movl	%edx, -40(%rbp)
	cmpl	$0, -40(%rbp)
	jne	LBB0_4
## %bb.3:                               ##   in Loop: Header=BB0_1 Depth=1
	jmp	LBB0_5
LBB0_4:                                 ##   in Loop: Header=BB0_1 Depth=1
	movl	-40(%rbp), %eax
	bsrl	%eax, %eax
	xorl	$31, %eax
	subl	-32(%rbp), %eax
	movl	%eax, -44(%rbp)
	movl	-40(%rbp), %eax
	movl	-44(%rbp), %ecx
                                        ## kill: def $cl killed $ecx
	shll	%cl, %eax
	subl	-4(%rbp), %eax
	movw	%ax, %dx
	movq	-24(%rbp), %rsi
	movslq	-36(%rbp), %rdi
	movw	%dx, (%rsi,%rdi,8)
	movl	-44(%rbp), %eax
	movw	%ax, %dx
	movq	-24(%rbp), %rsi
	movslq	-36(%rbp), %rdi
	movw	%dx, 2(%rsi,%rdi,8)
	movl	-28(%rbp), %eax
	subl	-40(%rbp), %eax
	movl	-4(%rbp), %r8d
	movl	-44(%rbp), %ecx
                                        ## kill: def $cl killed $ecx
	sarl	%cl, %r8d
	addl	%r8d, %eax
	movw	%ax, %dx
	movq	-24(%rbp), %rsi
	movslq	-36(%rbp), %rdi
	movw	%dx, 4(%rsi,%rdi,8)
	movl	-28(%rbp), %eax
	subl	-40(%rbp), %eax
	movl	-4(%rbp), %r8d
	movl	-44(%rbp), %r9d
	subl	$1, %r9d
	movl	%r9d, %ecx
                                        ## kill: def $cl killed $ecx
	sarl	%cl, %r8d
	addl	%r8d, %eax
	movw	%ax, %dx
	movq	-24(%rbp), %rsi
	movslq	-36(%rbp), %rdi
	movw	%dx, 6(%rsi,%rdi,8)
	movl	-40(%rbp), %eax
	addl	-28(%rbp), %eax
	movl	%eax, -28(%rbp)
LBB0_5:                                 ##   in Loop: Header=BB0_1 Depth=1
	movl	-36(%rbp), %eax
	addl	$1, %eax
	movl	%eax, -36(%rbp)
	jmp	LBB0_1
LBB0_6:
	popq	%rbp
	retq
	.cfi_endproc
                                        ## -- End function
	.private_extern	_fse_init_decoder_table ## -- Begin function fse_init_decoder_table
	.globl	_fse_init_decoder_table
	.p2align	4, 0x90
_fse_init_decoder_table:                ## @fse_init_decoder_table
	.cfi_startproc
## %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	subq	$112, %rsp
	movl	%edi, -44(%rbp)
	movl	%esi, -48(%rbp)
	movq	%rdx, -56(%rbp)
	movq	%rcx, -64(%rbp)
	cmpl	$256, -48(%rbp)         ## imm = 0x100
	setle	%al
	xorb	$-1, %al
	andb	$1, %al
	movzbl	%al, %esi
	movslq	%esi, %rcx
	cmpq	$0, %rcx
	je	LBB1_2
## %bb.1:
	leaq	L___func__.fse_init_decoder_table(%rip), %rdi
	leaq	L_.str(%rip), %rsi
	leaq	L_.str.1(%rip), %rcx
	movl	$60, %edx
	callq	___assert_rtn
LBB1_2:
	jmp	LBB1_3
LBB1_3:
	movq	-56(%rbp), %rax
	movslq	-48(%rbp), %rcx
	movslq	-44(%rbp), %rdx
	movq	%rax, -8(%rbp)
	movq	%rcx, -16(%rbp)
	movq	%rdx, -24(%rbp)
	movq	$0, -32(%rbp)
	movl	$0, -36(%rbp)
LBB1_4:                                 ## =>This Inner Loop Header: Depth=1
	movslq	-36(%rbp), %rax
	cmpq	-16(%rbp), %rax
	jae	LBB1_6
## %bb.5:                               ##   in Loop: Header=BB1_4 Depth=1
	movq	-8(%rbp), %rax
	movslq	-36(%rbp), %rcx
	movzwl	(%rax,%rcx,2), %edx
	movl	%edx, %eax
	addq	-32(%rbp), %rax
	movq	%rax, -32(%rbp)
	movl	-36(%rbp), %edx
	addl	$1, %edx
	movl	%edx, -36(%rbp)
	jmp	LBB1_4
LBB1_6:
	xorl	%eax, %eax
	movq	-32(%rbp), %rcx
	movq	-24(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	$4294967295, %esi       ## imm = 0xFFFFFFFF
	cmoval	%esi, %eax
	cmpl	$0, %eax
	sete	%dil
	xorb	$-1, %dil
	andb	$1, %dil
	movzbl	%dil, %eax
	movslq	%eax, %rcx
	cmpq	$0, %rcx
	je	LBB1_8
## %bb.7:
	leaq	L___func__.fse_init_decoder_table(%rip), %rdi
	leaq	L_.str(%rip), %rsi
	leaq	L_.str.2(%rip), %rcx
	movl	$61, %edx
	callq	___assert_rtn
LBB1_8:
	jmp	LBB1_9
LBB1_9:
	movl	-44(%rbp), %eax
	bsrl	%eax, %eax
	xorl	$31, %eax
	movl	%eax, -68(%rbp)
	movl	$0, -72(%rbp)
	movl	$0, -76(%rbp)
LBB1_10:                                ## =>This Loop Header: Depth=1
                                        ##     Child Loop BB1_16 Depth 2
	movl	-76(%rbp), %eax
	cmpl	-48(%rbp), %eax
	jge	LBB1_24
## %bb.11:                              ##   in Loop: Header=BB1_10 Depth=1
	movq	-56(%rbp), %rax
	movslq	-76(%rbp), %rcx
	movzwl	(%rax,%rcx,2), %edx
	movl	%edx, -80(%rbp)
	cmpl	$0, -80(%rbp)
	jne	LBB1_13
## %bb.12:                              ##   in Loop: Header=BB1_10 Depth=1
	jmp	LBB1_23
LBB1_13:                                ##   in Loop: Header=BB1_10 Depth=1
	movl	-80(%rbp), %eax
	addl	-72(%rbp), %eax
	movl	%eax, -72(%rbp)
	movl	-72(%rbp), %eax
	cmpl	-44(%rbp), %eax
	jle	LBB1_15
## %bb.14:
	movl	$-1, -40(%rbp)
	jmp	LBB1_25
LBB1_15:                                ##   in Loop: Header=BB1_10 Depth=1
	movl	-80(%rbp), %eax
	bsrl	%eax, %eax
	xorl	$31, %eax
	subl	-68(%rbp), %eax
	movl	%eax, -84(%rbp)
	movl	-44(%rbp), %eax
	shll	$1, %eax
	movl	-84(%rbp), %ecx
                                        ## kill: def $cl killed $ecx
	sarl	%cl, %eax
	subl	-80(%rbp), %eax
	movl	%eax, -88(%rbp)
	movl	$0, -92(%rbp)
LBB1_16:                                ##   Parent Loop BB1_10 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	movl	-92(%rbp), %eax
	cmpl	-80(%rbp), %eax
	jge	LBB1_22
## %bb.17:                              ##   in Loop: Header=BB1_16 Depth=2
	movl	-76(%rbp), %eax
	movb	%al, %cl
	movb	%cl, -95(%rbp)
	movl	-92(%rbp), %eax
	cmpl	-88(%rbp), %eax
	jge	LBB1_19
## %bb.18:                              ##   in Loop: Header=BB1_16 Depth=2
	movl	-84(%rbp), %eax
	movb	%al, %cl
	movb	%cl, -96(%rbp)
	movl	-80(%rbp), %eax
	addl	-92(%rbp), %eax
	movl	-84(%rbp), %ecx
                                        ## kill: def $cl killed $ecx
	shll	%cl, %eax
	subl	-44(%rbp), %eax
	movw	%ax, %dx
	movw	%dx, -94(%rbp)
	jmp	LBB1_20
LBB1_19:                                ##   in Loop: Header=BB1_16 Depth=2
	movl	-84(%rbp), %eax
	subl	$1, %eax
	movb	%al, %cl
	movb	%cl, -96(%rbp)
	movl	-92(%rbp), %eax
	subl	-88(%rbp), %eax
	movl	-84(%rbp), %edx
	subl	$1, %edx
	movl	%edx, %ecx
                                        ## kill: def $cl killed $ecx
	shll	%cl, %eax
	movw	%ax, %si
	movw	%si, -94(%rbp)
LBB1_20:                                ##   in Loop: Header=BB1_16 Depth=2
	movq	$-1, %rcx
	movq	-64(%rbp), %rax
	leaq	-96(%rbp), %rdx
	movq	%rax, %rdi
	movq	%rdx, %rsi
	movl	$4, %edx
	callq	___memcpy_chk
	movq	-64(%rbp), %rcx
	addq	$4, %rcx
	movq	%rcx, -64(%rbp)
	movq	%rax, -104(%rbp)        ## 8-byte Spill
## %bb.21:                              ##   in Loop: Header=BB1_16 Depth=2
	movl	-92(%rbp), %eax
	addl	$1, %eax
	movl	%eax, -92(%rbp)
	jmp	LBB1_16
LBB1_22:                                ##   in Loop: Header=BB1_10 Depth=1
	jmp	LBB1_23
LBB1_23:                                ##   in Loop: Header=BB1_10 Depth=1
	movl	-76(%rbp), %eax
	addl	$1, %eax
	movl	%eax, -76(%rbp)
	jmp	LBB1_10
LBB1_24:
	movl	$0, -40(%rbp)
LBB1_25:
	movl	-40(%rbp), %eax
	addq	$112, %rsp
	popq	%rbp
	retq
	.cfi_endproc
                                        ## -- End function
	.private_extern	_fse_init_value_decoder_table ## -- Begin function fse_init_value_decoder_table
	.globl	_fse_init_value_decoder_table
	.p2align	4, 0x90
_fse_init_value_decoder_table:          ## @fse_init_value_decoder_table
	.cfi_startproc
## %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	subq	$144, %rsp
	movl	%edi, -40(%rbp)
	movl	%esi, -44(%rbp)
	movq	%rdx, -56(%rbp)
	movq	%rcx, -64(%rbp)
	movq	%r8, -72(%rbp)
	movq	%r9, -80(%rbp)
	cmpl	$256, -44(%rbp)         ## imm = 0x100
	setle	%al
	xorb	$-1, %al
	andb	$1, %al
	movzbl	%al, %esi
	movslq	%esi, %rcx
	cmpq	$0, %rcx
	je	LBB2_2
## %bb.1:
	leaq	L___func__.fse_init_value_decoder_table(%rip), %rdi
	leaq	L_.str(%rip), %rsi
	leaq	L_.str.1(%rip), %rcx
	movl	$114, %edx
	callq	___assert_rtn
LBB2_2:
	jmp	LBB2_3
LBB2_3:
	movq	-56(%rbp), %rax
	movslq	-44(%rbp), %rcx
	movslq	-40(%rbp), %rdx
	movq	%rax, -8(%rbp)
	movq	%rcx, -16(%rbp)
	movq	%rdx, -24(%rbp)
	movq	$0, -32(%rbp)
	movl	$0, -36(%rbp)
LBB2_4:                                 ## =>This Inner Loop Header: Depth=1
	movslq	-36(%rbp), %rax
	cmpq	-16(%rbp), %rax
	jae	LBB2_6
## %bb.5:                               ##   in Loop: Header=BB2_4 Depth=1
	movq	-8(%rbp), %rax
	movslq	-36(%rbp), %rcx
	movzwl	(%rax,%rcx,2), %edx
	movl	%edx, %eax
	addq	-32(%rbp), %rax
	movq	%rax, -32(%rbp)
	movl	-36(%rbp), %edx
	addl	$1, %edx
	movl	%edx, -36(%rbp)
	jmp	LBB2_4
LBB2_6:
	xorl	%eax, %eax
	movq	-32(%rbp), %rcx
	movq	-24(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	$4294967295, %esi       ## imm = 0xFFFFFFFF
	cmoval	%esi, %eax
	cmpl	$0, %eax
	sete	%dil
	xorb	$-1, %dil
	andb	$1, %dil
	movzbl	%dil, %eax
	movslq	%eax, %rcx
	cmpq	$0, %rcx
	je	LBB2_8
## %bb.7:
	leaq	L___func__.fse_init_value_decoder_table(%rip), %rdi
	leaq	L_.str(%rip), %rsi
	leaq	L_.str.2(%rip), %rcx
	movl	$115, %edx
	callq	___assert_rtn
LBB2_8:
	jmp	LBB2_9
LBB2_9:
	movl	-40(%rbp), %eax
	bsrl	%eax, %eax
	xorl	$31, %eax
	movl	%eax, -84(%rbp)
	movl	$0, -88(%rbp)
LBB2_10:                                ## =>This Loop Header: Depth=1
                                        ##     Child Loop BB2_14 Depth 2
	movl	-88(%rbp), %eax
	cmpl	-44(%rbp), %eax
	jge	LBB2_22
## %bb.11:                              ##   in Loop: Header=BB2_10 Depth=1
	movq	-56(%rbp), %rax
	movslq	-88(%rbp), %rcx
	movzwl	(%rax,%rcx,2), %edx
	movl	%edx, -92(%rbp)
	cmpl	$0, -92(%rbp)
	jne	LBB2_13
## %bb.12:                              ##   in Loop: Header=BB2_10 Depth=1
	jmp	LBB2_21
LBB2_13:                                ##   in Loop: Header=BB2_10 Depth=1
	xorl	%esi, %esi
	movl	-92(%rbp), %eax
	bsrl	%eax, %eax
	xorl	$31, %eax
	subl	-84(%rbp), %eax
	movl	%eax, -96(%rbp)
	movl	-40(%rbp), %eax
	shll	$1, %eax
	movl	-96(%rbp), %ecx
                                        ## kill: def $cl killed $ecx
	sarl	%cl, %eax
	subl	-92(%rbp), %eax
	movl	%eax, -100(%rbp)
	leaq	-112(%rbp), %rdx
	movq	%rdx, %rdi
	movl	$8, %edx
	callq	_memset
	movq	-64(%rbp), %rdx
	movslq	-88(%rbp), %rdi
	movb	(%rdx,%rdi), %cl
	movb	%cl, -111(%rbp)
	movq	-72(%rbp), %rdx
	movslq	-88(%rbp), %rdi
	movl	(%rdx,%rdi,4), %eax
	movl	%eax, -108(%rbp)
	movl	$0, -116(%rbp)
LBB2_14:                                ##   Parent Loop BB2_10 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	movl	-116(%rbp), %eax
	cmpl	-92(%rbp), %eax
	jge	LBB2_20
## %bb.15:                              ##   in Loop: Header=BB2_14 Depth=2
	movq	-112(%rbp), %rax
	movq	%rax, -128(%rbp)
	movl	-116(%rbp), %ecx
	cmpl	-100(%rbp), %ecx
	jge	LBB2_17
## %bb.16:                              ##   in Loop: Header=BB2_14 Depth=2
	movl	-96(%rbp), %eax
	movb	%al, %cl
	movzbl	%cl, %eax
	movzbl	-127(%rbp), %edx
	addl	%edx, %eax
	movb	%al, %cl
	movb	%cl, -128(%rbp)
	movl	-92(%rbp), %eax
	addl	-116(%rbp), %eax
	movl	-96(%rbp), %ecx
                                        ## kill: def $cl killed $ecx
	shll	%cl, %eax
	subl	-40(%rbp), %eax
	movw	%ax, %si
	movw	%si, -126(%rbp)
	jmp	LBB2_18
LBB2_17:                                ##   in Loop: Header=BB2_14 Depth=2
	movl	-96(%rbp), %eax
	subl	$1, %eax
	movb	%al, %cl
	movzbl	%cl, %eax
	movzbl	-127(%rbp), %edx
	addl	%edx, %eax
	movb	%al, %cl
	movb	%cl, -128(%rbp)
	movl	-116(%rbp), %eax
	subl	-100(%rbp), %eax
	movl	-96(%rbp), %edx
	subl	$1, %edx
	movl	%edx, %ecx
                                        ## kill: def $cl killed $ecx
	shll	%cl, %eax
	movw	%ax, %si
	movw	%si, -126(%rbp)
LBB2_18:                                ##   in Loop: Header=BB2_14 Depth=2
	movq	$-1, %rcx
	movq	-80(%rbp), %rax
	leaq	-128(%rbp), %rdx
	movq	%rax, %rdi
	movq	%rdx, %rsi
	movl	$8, %edx
	callq	___memcpy_chk
	movq	-80(%rbp), %rcx
	addq	$8, %rcx
	movq	%rcx, -80(%rbp)
	movq	%rax, -136(%rbp)        ## 8-byte Spill
## %bb.19:                              ##   in Loop: Header=BB2_14 Depth=2
	movl	-116(%rbp), %eax
	addl	$1, %eax
	movl	%eax, -116(%rbp)
	jmp	LBB2_14
LBB2_20:                                ##   in Loop: Header=BB2_10 Depth=1
	jmp	LBB2_21
LBB2_21:                                ##   in Loop: Header=BB2_10 Depth=1
	movl	-88(%rbp), %eax
	addl	$1, %eax
	movl	%eax, -88(%rbp)
	jmp	LBB2_10
LBB2_22:
	addq	$144, %rsp
	popq	%rbp
	retq
	.cfi_endproc
                                        ## -- End function
	.private_extern	_fse_normalize_freq ## -- Begin function fse_normalize_freq
	.globl	_fse_normalize_freq
	.p2align	4, 0x90
_fse_normalize_freq:                    ## @fse_normalize_freq
	.cfi_startproc
## %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	subq	$64, %rsp
	movl	%edi, -4(%rbp)
	movl	%esi, -8(%rbp)
	movq	%rdx, -16(%rbp)
	movq	%rcx, -24(%rbp)
	movl	$0, -28(%rbp)
	movl	-4(%rbp), %esi
	movl	%esi, -32(%rbp)
	movl	$0, -36(%rbp)
	movl	$0, -40(%rbp)
	movl	-4(%rbp), %esi
	bsrl	%esi, %esi
	xorl	$31, %esi
	subl	$1, %esi
	movl	%esi, -44(%rbp)
	movl	$0, -52(%rbp)
LBB3_1:                                 ## =>This Inner Loop Header: Depth=1
	movl	-52(%rbp), %eax
	cmpl	-8(%rbp), %eax
	jge	LBB3_4
## %bb.2:                               ##   in Loop: Header=BB3_1 Depth=1
	movq	-16(%rbp), %rax
	movslq	-52(%rbp), %rcx
	movl	(%rax,%rcx,4), %edx
	addl	-28(%rbp), %edx
	movl	%edx, -28(%rbp)
## %bb.3:                               ##   in Loop: Header=BB3_1 Depth=1
	movl	-52(%rbp), %eax
	addl	$1, %eax
	movl	%eax, -52(%rbp)
	jmp	LBB3_1
LBB3_4:
	cmpl	$0, -28(%rbp)
	jne	LBB3_6
## %bb.5:
	movl	$0, -48(%rbp)
	jmp	LBB3_7
LBB3_6:
	movl	$2147483648, %eax       ## imm = 0x80000000
	xorl	%edx, %edx
	divl	-28(%rbp)
	movl	%eax, -48(%rbp)
LBB3_7:
	movl	$0, -56(%rbp)
LBB3_8:                                 ## =>This Inner Loop Header: Depth=1
	movl	-56(%rbp), %eax
	cmpl	-8(%rbp), %eax
	jge	LBB3_16
## %bb.9:                               ##   in Loop: Header=BB3_8 Depth=1
	movq	-16(%rbp), %rax
	movslq	-56(%rbp), %rcx
	movl	(%rax,%rcx,4), %edx
	imull	-48(%rbp), %edx
	movl	-44(%rbp), %ecx
                                        ## kill: def $cl killed $ecx
	shrl	%cl, %edx
	addl	$1, %edx
	shrl	$1, %edx
	movl	%edx, -60(%rbp)
	cmpl	$0, -60(%rbp)
	jne	LBB3_12
## %bb.10:                              ##   in Loop: Header=BB3_8 Depth=1
	movq	-16(%rbp), %rax
	movslq	-56(%rbp), %rcx
	cmpl	$0, (%rax,%rcx,4)
	je	LBB3_12
## %bb.11:                              ##   in Loop: Header=BB3_8 Depth=1
	movl	$1, -60(%rbp)
LBB3_12:                                ##   in Loop: Header=BB3_8 Depth=1
	movl	-60(%rbp), %eax
	movw	%ax, %cx
	movq	-24(%rbp), %rdx
	movslq	-56(%rbp), %rsi
	movw	%cx, (%rdx,%rsi,2)
	movl	-60(%rbp), %eax
	movl	-32(%rbp), %edi
	subl	%eax, %edi
	movl	%edi, -32(%rbp)
	movl	-60(%rbp), %eax
	cmpl	-36(%rbp), %eax
	jle	LBB3_14
## %bb.13:                              ##   in Loop: Header=BB3_8 Depth=1
	movl	-60(%rbp), %eax
	movl	%eax, -36(%rbp)
	movl	-56(%rbp), %eax
	movl	%eax, -40(%rbp)
LBB3_14:                                ##   in Loop: Header=BB3_8 Depth=1
	jmp	LBB3_15
LBB3_15:                                ##   in Loop: Header=BB3_8 Depth=1
	movl	-56(%rbp), %eax
	addl	$1, %eax
	movl	%eax, -56(%rbp)
	jmp	LBB3_8
LBB3_16:
	xorl	%eax, %eax
	subl	-32(%rbp), %eax
	movl	-36(%rbp), %ecx
	sarl	$2, %ecx
	cmpl	%ecx, %eax
	jge	LBB3_18
## %bb.17:
	movl	-32(%rbp), %eax
	movq	-24(%rbp), %rcx
	movslq	-40(%rbp), %rdx
	movzwl	(%rcx,%rdx,2), %esi
	addl	%eax, %esi
	movw	%si, %di
	movw	%di, (%rcx,%rdx,2)
	jmp	LBB3_19
LBB3_18:
	xorl	%eax, %eax
	movq	-24(%rbp), %rdi
	subl	-32(%rbp), %eax
	movl	-8(%rbp), %edx
	movl	%eax, %esi
	callq	_fse_adjust_freqs
LBB3_19:
	addq	$64, %rsp
	popq	%rbp
	retq
	.cfi_endproc
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function fse_adjust_freqs
_fse_adjust_freqs:                      ## @fse_adjust_freqs
	.cfi_startproc
## %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movl	%edx, -16(%rbp)
	movl	$3, -20(%rbp)
LBB4_1:                                 ## =>This Loop Header: Depth=1
                                        ##     Child Loop BB4_3 Depth 2
	cmpl	$0, -12(%rbp)
	je	LBB4_14
## %bb.2:                               ##   in Loop: Header=BB4_1 Depth=1
	movl	$0, -24(%rbp)
LBB4_3:                                 ##   Parent Loop BB4_1 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	movl	-24(%rbp), %eax
	cmpl	-16(%rbp), %eax
	jge	LBB4_12
## %bb.4:                               ##   in Loop: Header=BB4_3 Depth=2
	movq	-8(%rbp), %rax
	movslq	-24(%rbp), %rcx
	movzwl	(%rax,%rcx,2), %edx
	cmpl	$1, %edx
	jle	LBB4_10
## %bb.5:                               ##   in Loop: Header=BB4_3 Depth=2
	movq	-8(%rbp), %rax
	movslq	-24(%rbp), %rcx
	movzwl	(%rax,%rcx,2), %edx
	subl	$1, %edx
	movl	-20(%rbp), %ecx
                                        ## kill: def $cl killed $ecx
	sarl	%cl, %edx
	movl	%edx, -28(%rbp)
	movl	-28(%rbp), %edx
	cmpl	-12(%rbp), %edx
	jle	LBB4_7
## %bb.6:                               ##   in Loop: Header=BB4_3 Depth=2
	movl	-12(%rbp), %eax
	movl	%eax, -28(%rbp)
LBB4_7:                                 ##   in Loop: Header=BB4_3 Depth=2
	movl	-28(%rbp), %eax
	movq	-8(%rbp), %rcx
	movslq	-24(%rbp), %rdx
	movzwl	(%rcx,%rdx,2), %esi
	subl	%eax, %esi
	movw	%si, %di
	movw	%di, (%rcx,%rdx,2)
	movl	-28(%rbp), %eax
	movl	-12(%rbp), %esi
	subl	%eax, %esi
	movl	%esi, -12(%rbp)
	cmpl	$0, -12(%rbp)
	jne	LBB4_9
## %bb.8:                               ##   in Loop: Header=BB4_1 Depth=1
	jmp	LBB4_12
LBB4_9:                                 ##   in Loop: Header=BB4_3 Depth=2
	jmp	LBB4_10
LBB4_10:                                ##   in Loop: Header=BB4_3 Depth=2
	jmp	LBB4_11
LBB4_11:                                ##   in Loop: Header=BB4_3 Depth=2
	movl	-24(%rbp), %eax
	addl	$1, %eax
	movl	%eax, -24(%rbp)
	jmp	LBB4_3
LBB4_12:                                ##   in Loop: Header=BB4_1 Depth=1
	jmp	LBB4_13
LBB4_13:                                ##   in Loop: Header=BB4_1 Depth=1
	movl	-20(%rbp), %eax
	addl	$-1, %eax
	movl	%eax, -20(%rbp)
	jmp	LBB4_1
LBB4_14:
	popq	%rbp
	retq
	.cfi_endproc
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
