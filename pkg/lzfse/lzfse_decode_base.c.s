	.section	__TEXT,__text,regular,pure_instructions
	.build_version macos, 10, 15	sdk_version 10, 15
	.private_extern	_lzfse_decode   ## -- Begin function lzfse_decode
	.globl	_lzfse_decode
	.p2align	4, 0x90
_lzfse_decode:                          ## @lzfse_decode
	.cfi_startproc
## %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	subq	$1952, %rsp             ## imm = 0x7A0
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -704(%rbp)
LBB0_1:                                 ## =>This Loop Header: Depth=1
                                        ##     Child Loop BB0_30 Depth 2
                                        ##     Child Loop BB0_33 Depth 2
                                        ##     Child Loop BB0_36 Depth 2
                                        ##     Child Loop BB0_39 Depth 2
                                        ##     Child Loop BB0_61 Depth 2
	movq	-704(%rbp), %rax
	movl	52(%rax), %ecx
	testl	%ecx, %ecx
	movl	%ecx, -1772(%rbp)       ## 4-byte Spill
	je	LBB0_2
	jmp	LBB0_148
LBB0_148:                               ##   in Loop: Header=BB0_1 Depth=1
	movl	-1772(%rbp), %eax       ## 4-byte Reload
	subl	$762869346, %eax        ## imm = 0x2D787662
	movl	%eax, -1776(%rbp)       ## 4-byte Spill
	je	LBB0_107
	jmp	LBB0_149
LBB0_149:                               ##   in Loop: Header=BB0_1 Depth=1
	movl	-1772(%rbp), %eax       ## 4-byte Reload
	subl	$829978210, %eax        ## imm = 0x31787662
	movl	%eax, -1780(%rbp)       ## 4-byte Spill
	je	LBB0_118
	jmp	LBB0_150
LBB0_150:                               ##   in Loop: Header=BB0_1 Depth=1
	movl	-1772(%rbp), %eax       ## 4-byte Reload
	subl	$846755426, %eax        ## imm = 0x32787662
	movl	%eax, -1784(%rbp)       ## 4-byte Spill
	je	LBB0_118
	jmp	LBB0_151
LBB0_151:                               ##   in Loop: Header=BB0_1 Depth=1
	movl	-1772(%rbp), %eax       ## 4-byte Reload
	subl	$1853388386, %eax       ## imm = 0x6E787662
	movl	%eax, -1788(%rbp)       ## 4-byte Spill
	je	LBB0_124
	jmp	LBB0_143
LBB0_2:                                 ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	addq	$4, %rax
	movq	-704(%rbp), %rcx
	cmpq	16(%rcx), %rax
	jbe	LBB0_4
## %bb.3:
	movl	$-1, -696(%rbp)
	jmp	LBB0_145
LBB0_4:                                 ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -688(%rbp)
	movq	-688(%rbp), %rax
	movl	(%rax), %ecx
	movl	%ecx, -692(%rbp)
	movl	-692(%rbp), %ecx
	movl	%ecx, -708(%rbp)
	cmpl	$611874402, -708(%rbp)  ## imm = 0x24787662
	jne	LBB0_6
## %bb.5:
	movq	-704(%rbp), %rax
	movq	(%rax), %rcx
	addq	$4, %rcx
	movq	%rcx, (%rax)
	movq	-704(%rbp), %rax
	movl	$1, 48(%rax)
	movl	$0, -696(%rbp)
	jmp	LBB0_145
LBB0_6:                                 ##   in Loop: Header=BB0_1 Depth=1
	cmpl	$762869346, -708(%rbp)  ## imm = 0x2D787662
	jne	LBB0_10
## %bb.7:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	addq	$8, %rax
	movq	-704(%rbp), %rcx
	cmpq	16(%rcx), %rax
	jbe	LBB0_9
## %bb.8:
	movl	$-1, -696(%rbp)
	jmp	LBB0_145
LBB0_9:                                 ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	addq	$47364, %rax            ## imm = 0xB904
	movq	%rax, -720(%rbp)
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	addq	$4, %rax
	movq	%rax, -672(%rbp)
	movq	-672(%rbp), %rax
	movl	(%rax), %ecx
	movl	%ecx, -676(%rbp)
	movl	-676(%rbp), %ecx
	movq	-720(%rbp), %rax
	movl	%ecx, (%rax)
	movq	-704(%rbp), %rax
	movq	(%rax), %rdx
	addq	$8, %rdx
	movq	%rdx, (%rax)
	movl	-708(%rbp), %ecx
	movq	-704(%rbp), %rax
	movl	%ecx, 52(%rax)
	jmp	LBB0_144
LBB0_10:                                ##   in Loop: Header=BB0_1 Depth=1
	cmpl	$1853388386, -708(%rbp) ## imm = 0x6E787662
	jne	LBB0_14
## %bb.11:                              ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	addq	$12, %rax
	movq	-704(%rbp), %rcx
	cmpq	16(%rcx), %rax
	jbe	LBB0_13
## %bb.12:
	movl	$-1, -696(%rbp)
	jmp	LBB0_145
LBB0_13:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	addq	$47352, %rax            ## imm = 0xB8F8
	movq	%rax, -728(%rbp)
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	addq	$4, %rax
	movq	%rax, -624(%rbp)
	movq	-624(%rbp), %rax
	movl	(%rax), %ecx
	movl	%ecx, -628(%rbp)
	movl	-628(%rbp), %ecx
	movq	-728(%rbp), %rax
	movl	%ecx, (%rax)
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	addq	$8, %rax
	movq	%rax, -608(%rbp)
	movq	-608(%rbp), %rax
	movl	(%rax), %ecx
	movl	%ecx, -612(%rbp)
	movl	-612(%rbp), %ecx
	movq	-728(%rbp), %rax
	movl	%ecx, 4(%rax)
	movq	-728(%rbp), %rax
	movl	$0, 8(%rax)
	movq	-704(%rbp), %rax
	movq	(%rax), %rdx
	addq	$12, %rdx
	movq	%rdx, (%rax)
	movl	-708(%rbp), %ecx
	movq	-704(%rbp), %rax
	movl	%ecx, 52(%rax)
	jmp	LBB0_144
LBB0_14:                                ##   in Loop: Header=BB0_1 Depth=1
	cmpl	$829978210, -708(%rbp)  ## imm = 0x31787662
	je	LBB0_16
## %bb.15:                              ##   in Loop: Header=BB0_1 Depth=1
	cmpl	$846755426, -708(%rbp)  ## imm = 0x32787662
	jne	LBB0_106
LBB0_16:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	$0, -1512(%rbp)
	cmpl	$846755426, -708(%rbp)  ## imm = 0x32787662
	jne	LBB0_24
## %bb.17:                              ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	addq	$32, %rax
	movq	-704(%rbp), %rcx
	cmpq	16(%rcx), %rax
	jbe	LBB0_19
## %bb.18:
	movl	$-1, -696(%rbp)
	jmp	LBB0_145
LBB0_19:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -1520(%rbp)
	movq	-1520(%rbp), %rdi
	callq	_lzfse_decode_v2_header_size
	movl	%eax, %eax
	movl	%eax, %edi
	movq	%rdi, -1512(%rbp)
	movq	-704(%rbp), %rdi
	movq	(%rdi), %rdi
	addq	-1512(%rbp), %rdi
	movq	-704(%rbp), %rcx
	cmpq	16(%rcx), %rdi
	jbe	LBB0_21
## %bb.20:
	movl	$-1, -696(%rbp)
	jmp	LBB0_145
LBB0_21:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	-1520(%rbp), %rsi
	leaq	-1504(%rbp), %rdi
	callq	_lzfse_decode_v1
	movl	%eax, -1524(%rbp)
	cmpl	$0, -1524(%rbp)
	je	LBB0_23
## %bb.22:
	movl	$-3, -696(%rbp)
	jmp	LBB0_145
LBB0_23:                                ##   in Loop: Header=BB0_1 Depth=1
	jmp	LBB0_27
LBB0_24:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	addq	$772, %rax              ## imm = 0x304
	movq	-704(%rbp), %rcx
	cmpq	16(%rcx), %rax
	jbe	LBB0_26
## %bb.25:
	movl	$-1, -696(%rbp)
	jmp	LBB0_145
LBB0_26:                                ##   in Loop: Header=BB0_1 Depth=1
	leaq	-1504(%rbp), %rax
	movq	-704(%rbp), %rcx
	movq	(%rcx), %rsi
	movq	%rax, %rdi
	movl	$772, %edx              ## imm = 0x304
	callq	_memcpy
	movq	$772, -1512(%rbp)       ## imm = 0x304
LBB0_27:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	addq	-1512(%rbp), %rax
	movl	-1484(%rbp), %ecx
	movl	%ecx, %edx
	addq	%rdx, %rax
	movl	-1480(%rbp), %ecx
	movl	%ecx, %edx
	addq	%rdx, %rax
	movq	-704(%rbp), %rdx
	cmpq	16(%rdx), %rax
	jbe	LBB0_29
## %bb.28:
	movl	$-1, -696(%rbp)
	jmp	LBB0_145
LBB0_29:                                ##   in Loop: Header=BB0_1 Depth=1
	xorl	%eax, %eax
	leaq	-1504(%rbp), %rcx
	movq	%rcx, -512(%rbp)
	movl	$0, -516(%rbp)
	movl	-516(%rbp), %edx
	movq	-512(%rbp), %rcx
	movl	(%rcx), %esi
	cmpl	$829978210, %esi        ## imm = 0x31787662
	movl	$1, %esi
	cmovel	%eax, %esi
	orl	%esi, %edx
	movl	%edx, -516(%rbp)
	movl	-516(%rbp), %edx
	movq	-512(%rbp), %rcx
	movl	12(%rcx), %esi
	cmpl	$40000, %esi            ## imm = 0x9C40
	movl	$2, %esi
	cmovbel	%eax, %esi
	orl	%esi, %edx
	movl	%edx, -516(%rbp)
	movl	-516(%rbp), %edx
	movq	-512(%rbp), %rcx
	movl	16(%rcx), %esi
	cmpl	$10000, %esi            ## imm = 0x2710
	movl	$4, %esi
	cmovbel	%eax, %esi
	orl	%esi, %edx
	movl	%edx, -516(%rbp)
	movq	-512(%rbp), %rcx
	movq	32(%rcx), %rcx
	movq	%rcx, -16(%rbp)
	movl	-516(%rbp), %edx
	movzwl	-16(%rbp), %esi
	cmpl	$1024, %esi             ## imm = 0x400
	movl	$8, %esi
	cmovll	%eax, %esi
	orl	%esi, %edx
	movl	%edx, -516(%rbp)
	movl	-516(%rbp), %edx
	movzwl	-14(%rbp), %esi
	cmpl	$1024, %esi             ## imm = 0x400
	movl	$16, %esi
	cmovll	%eax, %esi
	orl	%esi, %edx
	movl	%edx, -516(%rbp)
	movl	-516(%rbp), %edx
	movzwl	-12(%rbp), %esi
	cmpl	$1024, %esi             ## imm = 0x400
	movl	$32, %esi
	cmovll	%eax, %esi
	orl	%esi, %edx
	movl	%edx, -516(%rbp)
	movl	-516(%rbp), %edx
	movzwl	-10(%rbp), %esi
	cmpl	$1024, %esi             ## imm = 0x400
	movl	$64, %esi
	cmovll	%eax, %esi
	orl	%esi, %edx
	movl	%edx, -516(%rbp)
	movl	-516(%rbp), %edx
	movq	-512(%rbp), %rcx
	movzwl	44(%rcx), %esi
	cmpl	$64, %esi
	movl	$128, %esi
	cmovll	%eax, %esi
	orl	%esi, %edx
	movl	%edx, -516(%rbp)
	movl	-516(%rbp), %edx
	movq	-512(%rbp), %rcx
	movzwl	46(%rcx), %esi
	cmpl	$64, %esi
	movl	$256, %esi              ## imm = 0x100
	cmovll	%eax, %esi
	orl	%esi, %edx
	movl	%edx, -516(%rbp)
	movl	-516(%rbp), %edx
	movq	-512(%rbp), %rcx
	movzwl	48(%rcx), %esi
	cmpl	$256, %esi              ## imm = 0x100
	movl	$512, %esi              ## imm = 0x200
	cmovll	%eax, %esi
	orl	%esi, %edx
	movl	%edx, -516(%rbp)
	movq	-512(%rbp), %rcx
	addq	$50, %rcx
	movq	%rcx, -472(%rbp)
	movq	$20, -480(%rbp)
	movq	$64, -488(%rbp)
	movq	$0, -496(%rbp)
	movl	$0, -500(%rbp)
LBB0_30:                                ##   Parent Loop BB0_1 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	movslq	-500(%rbp), %rax
	cmpq	-480(%rbp), %rax
	jae	LBB0_32
## %bb.31:                              ##   in Loop: Header=BB0_30 Depth=2
	movq	-472(%rbp), %rax
	movslq	-500(%rbp), %rcx
	movzwl	(%rax,%rcx,2), %edx
	movl	%edx, %eax
	addq	-496(%rbp), %rax
	movq	%rax, -496(%rbp)
	movl	-500(%rbp), %edx
	addl	$1, %edx
	movl	%edx, -500(%rbp)
	jmp	LBB0_30
LBB0_32:                                ##   in Loop: Header=BB0_1 Depth=1
	xorl	%eax, %eax
	movq	-496(%rbp), %rcx
	movq	-488(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	$4294967295, %esi       ## imm = 0xFFFFFFFF
	movl	%eax, %edi
	cmoval	%esi, %edi
	movl	%edi, -520(%rbp)
	movl	-516(%rbp), %esi
	movl	-520(%rbp), %edi
	cmpl	$0, %edi
	movl	$1024, %edi             ## imm = 0x400
	cmovel	%eax, %edi
	orl	%edi, %esi
	movl	%esi, -516(%rbp)
	movq	-512(%rbp), %rcx
	addq	$90, %rcx
	movq	%rcx, -352(%rbp)
	movq	$20, -360(%rbp)
	movq	$64, -368(%rbp)
	movq	$0, -376(%rbp)
	movl	$0, -380(%rbp)
LBB0_33:                                ##   Parent Loop BB0_1 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	movslq	-380(%rbp), %rax
	cmpq	-360(%rbp), %rax
	jae	LBB0_35
## %bb.34:                              ##   in Loop: Header=BB0_33 Depth=2
	movq	-352(%rbp), %rax
	movslq	-380(%rbp), %rcx
	movzwl	(%rax,%rcx,2), %edx
	movl	%edx, %eax
	addq	-376(%rbp), %rax
	movq	%rax, -376(%rbp)
	movl	-380(%rbp), %edx
	addl	$1, %edx
	movl	%edx, -380(%rbp)
	jmp	LBB0_33
LBB0_35:                                ##   in Loop: Header=BB0_1 Depth=1
	xorl	%eax, %eax
	movq	-376(%rbp), %rcx
	movq	-368(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	$4294967295, %esi       ## imm = 0xFFFFFFFF
	movl	%eax, %edi
	cmoval	%esi, %edi
	movl	%edi, -520(%rbp)
	movl	-516(%rbp), %esi
	movl	-520(%rbp), %edi
	cmpl	$0, %edi
	movl	$2048, %edi             ## imm = 0x800
	cmovel	%eax, %edi
	orl	%edi, %esi
	movl	%esi, -516(%rbp)
	movq	-512(%rbp), %rcx
	addq	$130, %rcx
	movq	%rcx, -392(%rbp)
	movq	$64, -400(%rbp)
	movq	$256, -408(%rbp)        ## imm = 0x100
	movq	$0, -416(%rbp)
	movl	$0, -420(%rbp)
LBB0_36:                                ##   Parent Loop BB0_1 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	movslq	-420(%rbp), %rax
	cmpq	-400(%rbp), %rax
	jae	LBB0_38
## %bb.37:                              ##   in Loop: Header=BB0_36 Depth=2
	movq	-392(%rbp), %rax
	movslq	-420(%rbp), %rcx
	movzwl	(%rax,%rcx,2), %edx
	movl	%edx, %eax
	addq	-416(%rbp), %rax
	movq	%rax, -416(%rbp)
	movl	-420(%rbp), %edx
	addl	$1, %edx
	movl	%edx, -420(%rbp)
	jmp	LBB0_36
LBB0_38:                                ##   in Loop: Header=BB0_1 Depth=1
	xorl	%eax, %eax
	movq	-416(%rbp), %rcx
	movq	-408(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	$4294967295, %esi       ## imm = 0xFFFFFFFF
	movl	%eax, %edi
	cmoval	%esi, %edi
	movl	%edi, -520(%rbp)
	movl	-516(%rbp), %esi
	movl	-520(%rbp), %edi
	cmpl	$0, %edi
	movl	$4096, %edi             ## imm = 0x1000
	cmovel	%eax, %edi
	orl	%edi, %esi
	movl	%esi, -516(%rbp)
	movq	-512(%rbp), %rcx
	addq	$258, %rcx              ## imm = 0x102
	movq	%rcx, -432(%rbp)
	movq	$256, -440(%rbp)        ## imm = 0x100
	movq	$1024, -448(%rbp)       ## imm = 0x400
	movq	$0, -456(%rbp)
	movl	$0, -460(%rbp)
LBB0_39:                                ##   Parent Loop BB0_1 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	movslq	-460(%rbp), %rax
	cmpq	-440(%rbp), %rax
	jae	LBB0_41
## %bb.40:                              ##   in Loop: Header=BB0_39 Depth=2
	movq	-432(%rbp), %rax
	movslq	-460(%rbp), %rcx
	movzwl	(%rax,%rcx,2), %edx
	movl	%edx, %eax
	addq	-456(%rbp), %rax
	movq	%rax, -456(%rbp)
	movl	-460(%rbp), %edx
	addl	$1, %edx
	movl	%edx, -460(%rbp)
	jmp	LBB0_39
LBB0_41:                                ##   in Loop: Header=BB0_1 Depth=1
	xorl	%eax, %eax
	movq	-456(%rbp), %rcx
	movq	-448(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	$4294967295, %esi       ## imm = 0xFFFFFFFF
	movl	%eax, %edi
	cmoval	%esi, %edi
	movl	%edi, -520(%rbp)
	movl	-516(%rbp), %esi
	movl	-520(%rbp), %edi
	cmpl	$0, %edi
	movl	$8192, %edi             ## imm = 0x2000
	cmovel	%eax, %edi
	orl	%edi, %esi
	movl	%esi, -516(%rbp)
	cmpl	$0, -516(%rbp)
	je	LBB0_43
## %bb.42:                              ##   in Loop: Header=BB0_1 Depth=1
	movl	-516(%rbp), %eax
	orl	$-2147483648, %eax      ## imm = 0x80000000
	movl	%eax, -504(%rbp)
	jmp	LBB0_44
LBB0_43:                                ##   in Loop: Header=BB0_1 Depth=1
	movl	$0, -504(%rbp)
LBB0_44:                                ##   in Loop: Header=BB0_1 Depth=1
	cmpl	$0, -504(%rbp)
	je	LBB0_46
## %bb.45:
	movl	$-3, -696(%rbp)
	jmp	LBB0_145
LBB0_46:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	-1512(%rbp), %rax
	movq	-704(%rbp), %rcx
	addq	(%rcx), %rax
	movq	%rax, (%rcx)
	movq	-704(%rbp), %rax
	addq	$56, %rax
	movq	%rax, -1536(%rbp)
	movl	-1480(%rbp), %edx
	movq	-1536(%rbp), %rax
	movl	%edx, 4(%rax)
	movl	-1488(%rbp), %edx
	movq	-1536(%rbp), %rax
	movl	%edx, (%rax)
	leaq	-1504(%rbp), %rax
	addq	$258, %rax              ## imm = 0x102
	movq	-1536(%rbp), %rcx
	addq	$3136, %rcx             ## imm = 0xC40
	movl	$1024, %edi             ## imm = 0x400
	movl	$256, %esi              ## imm = 0x100
	movq	%rax, %rdx
	callq	_fse_init_decoder_table
	leaq	-1504(%rbp), %rcx
	addq	$50, %rcx
	movq	-1536(%rbp), %rdx
	addq	$64, %rdx
	movl	$64, %edi
	movl	$20, %esi
	movq	%rdx, -1800(%rbp)       ## 8-byte Spill
	movq	%rcx, %rdx
	leaq	_l_extra_bits(%rip), %rcx
	leaq	_l_base_value(%rip), %r8
	movq	-1800(%rbp), %r9        ## 8-byte Reload
	movl	%eax, -1804(%rbp)       ## 4-byte Spill
	callq	_fse_init_value_decoder_table
	leaq	-1504(%rbp), %rcx
	addq	$90, %rcx
	movq	-1536(%rbp), %rdx
	addq	$576, %rdx              ## imm = 0x240
	movl	$64, %edi
	movl	$20, %esi
	movq	%rdx, -1816(%rbp)       ## 8-byte Spill
	movq	%rcx, %rdx
	leaq	_m_extra_bits(%rip), %rcx
	leaq	_m_base_value(%rip), %r8
	movq	-1816(%rbp), %r9        ## 8-byte Reload
	callq	_fse_init_value_decoder_table
	leaq	-1504(%rbp), %rcx
	addq	$130, %rcx
	movq	-1536(%rbp), %rdx
	addq	$1088, %rdx             ## imm = 0x440
	movl	$256, %edi              ## imm = 0x100
	movl	$64, %esi
	movq	%rdx, -1824(%rbp)       ## 8-byte Spill
	movq	%rcx, %rdx
	leaq	_d_extra_bits(%rip), %rcx
	leaq	_d_base_value(%rip), %r8
	movq	-1824(%rbp), %r9        ## 8-byte Reload
	callq	_fse_init_value_decoder_table
	movq	-704(%rbp), %rcx
	movq	8(%rcx), %rcx
	movq	%rcx, -1560(%rbp)
	movl	-1484(%rbp), %eax
	movq	-704(%rbp), %rcx
	movq	(%rcx), %rdx
	movl	%eax, %eax
	movl	%eax, %r8d
	addq	%r8, %rdx
	movq	%rdx, (%rcx)
	movq	-704(%rbp), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -1568(%rbp)
	movl	-1476(%rbp), %eax
	movq	-1560(%rbp), %rcx
	leaq	-1552(%rbp), %rdx
	movq	%rdx, -320(%rbp)
	movl	%eax, -324(%rbp)
	leaq	-1568(%rbp), %rdx
	movq	%rdx, -336(%rbp)
	movq	%rcx, -344(%rbp)
	cmpl	$0, -324(%rbp)
	je	LBB0_50
## %bb.47:                              ##   in Loop: Header=BB0_1 Depth=1
	movq	-336(%rbp), %rax
	movq	(%rax), %rax
	movq	-344(%rbp), %rcx
	addq	$8, %rcx
	cmpq	%rcx, %rax
	jae	LBB0_49
## %bb.48:                              ##   in Loop: Header=BB0_1 Depth=1
	movl	$-1, -308(%rbp)
	jmp	LBB0_58
LBB0_49:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	$-1, %rcx
	movq	-336(%rbp), %rax
	movq	(%rax), %rdx
	addq	$-8, %rdx
	movq	%rdx, (%rax)
	movq	-320(%rbp), %rax
	movq	-336(%rbp), %rdx
	movq	(%rdx), %rsi
	movq	%rax, %rdi
	movl	$8, %edx
	callq	___memcpy_chk
	movl	-324(%rbp), %r8d
	addl	$64, %r8d
	movq	-320(%rbp), %rcx
	movl	%r8d, 8(%rcx)
	movq	%rax, -1832(%rbp)       ## 8-byte Spill
	jmp	LBB0_53
LBB0_50:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	-336(%rbp), %rax
	movq	(%rax), %rax
	movq	-344(%rbp), %rcx
	addq	$7, %rcx
	cmpq	%rcx, %rax
	jae	LBB0_52
## %bb.51:                              ##   in Loop: Header=BB0_1 Depth=1
	movl	$-1, -308(%rbp)
	jmp	LBB0_58
LBB0_52:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	$-1, %rcx
	movq	-336(%rbp), %rax
	movq	(%rax), %rdx
	addq	$-7, %rdx
	movq	%rdx, (%rax)
	movq	-320(%rbp), %rax
	movq	-336(%rbp), %rdx
	movq	(%rdx), %rsi
	movq	%rax, %rdi
	movl	$7, %edx
	callq	___memcpy_chk
	movq	-320(%rbp), %rcx
	movabsq	$72057594037927935, %rdx ## imm = 0xFFFFFFFFFFFFFF
	andq	(%rcx), %rdx
	movq	%rdx, (%rcx)
	movl	-324(%rbp), %r8d
	addl	$56, %r8d
	movq	-320(%rbp), %rcx
	movl	%r8d, 8(%rcx)
	movq	%rax, -1840(%rbp)       ## 8-byte Spill
LBB0_53:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	-320(%rbp), %rax
	cmpl	$56, 8(%rax)
	jl	LBB0_56
## %bb.54:                              ##   in Loop: Header=BB0_1 Depth=1
	movq	-320(%rbp), %rax
	cmpl	$64, 8(%rax)
	jge	LBB0_56
## %bb.55:                              ##   in Loop: Header=BB0_1 Depth=1
	movq	-320(%rbp), %rax
	movq	(%rax), %rax
	movq	-320(%rbp), %rcx
	movl	8(%rcx), %edx
	movl	%edx, %ecx
                                        ## kill: def $cl killed $rcx
	shrq	%cl, %rax
	cmpq	$0, %rax
	je	LBB0_57
LBB0_56:                                ##   in Loop: Header=BB0_1 Depth=1
	movl	$-1, -308(%rbp)
	jmp	LBB0_58
LBB0_57:                                ##   in Loop: Header=BB0_1 Depth=1
	movl	$0, -308(%rbp)
LBB0_58:                                ##   in Loop: Header=BB0_1 Depth=1
	cmpl	$0, -308(%rbp)
	je	LBB0_60
## %bb.59:
	movl	$-3, -696(%rbp)
	jmp	LBB0_145
LBB0_60:                                ##   in Loop: Header=BB0_1 Depth=1
	movw	-1472(%rbp), %ax
	movw	%ax, -1570(%rbp)
	movw	-1470(%rbp), %ax
	movw	%ax, -1572(%rbp)
	movw	-1468(%rbp), %ax
	movw	%ax, -1574(%rbp)
	movw	-1466(%rbp), %ax
	movw	%ax, -1576(%rbp)
	movl	$0, -1580(%rbp)
LBB0_61:                                ##   Parent Loop BB0_1 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	movl	-1580(%rbp), %eax
	cmpl	-1492(%rbp), %eax
	jae	LBB0_91
## %bb.62:                              ##   in Loop: Header=BB0_61 Depth=2
	xorl	%eax, %eax
	movl	%eax, %ecx
	movq	-1560(%rbp), %rdx
	leaq	-1552(%rbp), %rsi
	movq	%rsi, -264(%rbp)
	leaq	-1568(%rbp), %rsi
	movq	%rsi, -272(%rbp)
	movq	%rdx, -280(%rbp)
	movq	-264(%rbp), %rdx
	movl	$63, %eax
	subl	8(%rdx), %eax
	andl	$-8, %eax
	movl	%eax, -284(%rbp)
	movq	-272(%rbp), %rdx
	movq	(%rdx), %rdx
	movl	-284(%rbp), %eax
	sarl	$3, %eax
	movslq	%eax, %rsi
	subq	%rsi, %rcx
	addq	%rcx, %rdx
	movq	%rdx, -296(%rbp)
	movq	-296(%rbp), %rcx
	cmpq	-280(%rbp), %rcx
	jae	LBB0_64
## %bb.63:                              ##   in Loop: Header=BB0_61 Depth=2
	movl	$-1, -256(%rbp)
	jmp	LBB0_71
LBB0_64:                                ##   in Loop: Header=BB0_61 Depth=2
	movq	-296(%rbp), %rax
	movq	-272(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-296(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -304(%rbp)
	movq	-264(%rbp), %rax
	movq	(%rax), %rax
	movl	-284(%rbp), %edx
	movl	%edx, %ecx
                                        ## kill: def $cl killed $rcx
	shlq	%cl, %rax
	movq	-304(%rbp), %rdi
	movl	-284(%rbp), %esi
	movq	%rax, -1848(%rbp)       ## 8-byte Spill
	callq	_fse_mask_lsb64
	xorl	%edx, %edx
	movb	%dl, %cl
	movq	-1848(%rbp), %rdi       ## 8-byte Reload
	orq	%rax, %rdi
	movq	-264(%rbp), %rax
	movq	%rdi, (%rax)
	movl	-284(%rbp), %edx
	movq	-264(%rbp), %rax
	addl	8(%rax), %edx
	movl	%edx, 8(%rax)
	movq	-264(%rbp), %rax
	cmpl	$56, 8(%rax)
	movb	%cl, -1849(%rbp)        ## 1-byte Spill
	jl	LBB0_66
## %bb.65:                              ##   in Loop: Header=BB0_61 Depth=2
	movq	-264(%rbp), %rax
	cmpl	$64, 8(%rax)
	setl	%cl
	movb	%cl, -1849(%rbp)        ## 1-byte Spill
LBB0_66:                                ##   in Loop: Header=BB0_61 Depth=2
	movb	-1849(%rbp), %al        ## 1-byte Reload
	xorb	$-1, %al
	testb	$1, %al
	jne	LBB0_67
	jmp	LBB0_68
LBB0_67:
	leaq	L___func__.fse_in_checked_flush64(%rip), %rdi
	leaq	L_.str.2(%rip), %rsi
	leaq	L_.str.3(%rip), %rcx
	movl	$376, %edx              ## imm = 0x178
	callq	___assert_rtn
LBB0_68:                                ##   in Loop: Header=BB0_61 Depth=2
	movq	-264(%rbp), %rax
	movq	(%rax), %rax
	movq	-264(%rbp), %rcx
	movl	8(%rcx), %edx
	movl	%edx, %ecx
                                        ## kill: def $cl killed $rcx
	shrq	%cl, %rax
	cmpq	$0, %rax
	sete	%cl
	xorb	$-1, %cl
	testb	$1, %cl
	jne	LBB0_69
	jmp	LBB0_70
LBB0_69:
	leaq	L___func__.fse_in_checked_flush64(%rip), %rdi
	leaq	L_.str.2(%rip), %rsi
	leaq	L_.str.4(%rip), %rcx
	movl	$376, %edx              ## imm = 0x178
	callq	___assert_rtn
LBB0_70:                                ##   in Loop: Header=BB0_61 Depth=2
	movl	$0, -256(%rbp)
LBB0_71:                                ##   in Loop: Header=BB0_61 Depth=2
	cmpl	$0, -256(%rbp)
	je	LBB0_73
## %bb.72:
	movl	$-3, -696(%rbp)
	jmp	LBB0_145
LBB0_73:                                ##   in Loop: Header=BB0_61 Depth=2
	xorl	%eax, %eax
	movb	%al, %cl
	movq	-1536(%rbp), %rdx
	addq	$3136, %rdx             ## imm = 0xC40
	leaq	-1570(%rbp), %rsi
	movq	%rsi, -232(%rbp)
	movq	%rdx, -240(%rbp)
	leaq	-1552(%rbp), %rdx
	movq	%rdx, -248(%rbp)
	movq	-240(%rbp), %rdx
	movq	-232(%rbp), %rsi
	movzwl	(%rsi), %eax
	movl	%eax, %esi
	movl	(%rdx,%rsi,4), %eax
	movl	%eax, -252(%rbp)
	movl	-252(%rbp), %eax
	sarl	$16, %eax
	movw	%ax, %di
	movzwl	%di, %eax
	movq	-248(%rbp), %rdx
	movl	-252(%rbp), %r8d
	andl	$255, %r8d
	movq	%rdx, -208(%rbp)
	movl	%r8d, -212(%rbp)
	cmpl	$0, -212(%rbp)
	movl	%eax, -1856(%rbp)       ## 4-byte Spill
	movb	%cl, -1857(%rbp)        ## 1-byte Spill
	jl	LBB0_75
## %bb.74:                              ##   in Loop: Header=BB0_61 Depth=2
	movl	-212(%rbp), %eax
	movq	-208(%rbp), %rcx
	cmpl	8(%rcx), %eax
	setle	%dl
	movb	%dl, -1857(%rbp)        ## 1-byte Spill
LBB0_75:                                ##   in Loop: Header=BB0_61 Depth=2
	movb	-1857(%rbp), %al        ## 1-byte Reload
	xorb	$-1, %al
	testb	$1, %al
	jne	LBB0_76
	jmp	LBB0_77
LBB0_76:
	leaq	L___func__.fse_in_pull64(%rip), %rdi
	leaq	L_.str.2(%rip), %rsi
	leaq	L_.str.5(%rip), %rcx
	movl	$408, %edx              ## imm = 0x198
	callq	___assert_rtn
LBB0_77:                                ##   in Loop: Header=BB0_61 Depth=2
	movl	-212(%rbp), %eax
	movq	-208(%rbp), %rcx
	movl	8(%rcx), %edx
	subl	%eax, %edx
	movl	%edx, 8(%rcx)
	movq	-208(%rbp), %rcx
	movq	(%rcx), %rcx
	movq	-208(%rbp), %rsi
	movl	8(%rsi), %eax
	movl	%eax, %esi
	movq	%rcx, -1872(%rbp)       ## 8-byte Spill
	movq	%rsi, %rcx
                                        ## kill: def $cl killed $rcx
	movq	-1872(%rbp), %rsi       ## 8-byte Reload
	shrq	%cl, %rsi
	movq	%rsi, -224(%rbp)
	movq	-208(%rbp), %rsi
	movq	(%rsi), %rdi
	movq	-208(%rbp), %rsi
	movl	8(%rsi), %esi
	callq	_fse_mask_lsb64
	movq	-208(%rbp), %rdi
	movq	%rax, (%rdi)
	movq	-224(%rbp), %rax
	movw	%ax, %r8w
	movzwl	%r8w, %edx
	movl	-1856(%rbp), %esi       ## 4-byte Reload
	addl	%edx, %esi
	movw	%si, %r8w
	movq	-232(%rbp), %rax
	movw	%r8w, (%rax)
	movslq	-252(%rbp), %rax
	movq	%rax, -192(%rbp)
	movl	$8, -196(%rbp)
	movl	$8, -200(%rbp)
	movq	-192(%rbp), %rax
	movl	-196(%rbp), %edx
	movl	%edx, %ecx
                                        ## kill: def $cl killed $rcx
	shrq	%cl, %rax
	movl	-200(%rbp), %esi
	movq	%rax, %rdi
	callq	_fse_mask_lsb64
	xorl	%edx, %edx
	movb	%dl, %cl
	movq	%rax, -184(%rbp)
	movq	-184(%rbp), %rax
	movb	%al, %r9b
	movq	-1536(%rbp), %rax
	movl	-1580(%rbp), %edx
	addl	$0, %edx
	movl	%edx, %edx
	movl	%edx, %edi
	movb	%r9b, 7232(%rax,%rdi)
	movq	-1536(%rbp), %rax
	addq	$3136, %rax             ## imm = 0xC40
	leaq	-1572(%rbp), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, -160(%rbp)
	leaq	-1552(%rbp), %rax
	movq	%rax, -168(%rbp)
	movq	-160(%rbp), %rax
	movq	-152(%rbp), %rdi
	movzwl	(%rdi), %edx
	movl	%edx, %edi
	movl	(%rax,%rdi,4), %edx
	movl	%edx, -172(%rbp)
	movl	-172(%rbp), %edx
	sarl	$16, %edx
	movw	%dx, %r8w
	movzwl	%r8w, %edx
	movq	-168(%rbp), %rax
	movl	-172(%rbp), %esi
	andl	$255, %esi
	movq	%rax, -128(%rbp)
	movl	%esi, -132(%rbp)
	cmpl	$0, -132(%rbp)
	movl	%edx, -1876(%rbp)       ## 4-byte Spill
	movb	%cl, -1877(%rbp)        ## 1-byte Spill
	jl	LBB0_79
## %bb.78:                              ##   in Loop: Header=BB0_61 Depth=2
	movl	-132(%rbp), %eax
	movq	-128(%rbp), %rcx
	cmpl	8(%rcx), %eax
	setle	%dl
	movb	%dl, -1877(%rbp)        ## 1-byte Spill
LBB0_79:                                ##   in Loop: Header=BB0_61 Depth=2
	movb	-1877(%rbp), %al        ## 1-byte Reload
	xorb	$-1, %al
	testb	$1, %al
	jne	LBB0_80
	jmp	LBB0_81
LBB0_80:
	leaq	L___func__.fse_in_pull64(%rip), %rdi
	leaq	L_.str.2(%rip), %rsi
	leaq	L_.str.5(%rip), %rcx
	movl	$408, %edx              ## imm = 0x198
	callq	___assert_rtn
LBB0_81:                                ##   in Loop: Header=BB0_61 Depth=2
	movl	-132(%rbp), %eax
	movq	-128(%rbp), %rcx
	movl	8(%rcx), %edx
	subl	%eax, %edx
	movl	%edx, 8(%rcx)
	movq	-128(%rbp), %rcx
	movq	(%rcx), %rcx
	movq	-128(%rbp), %rsi
	movl	8(%rsi), %eax
	movl	%eax, %esi
	movq	%rcx, -1888(%rbp)       ## 8-byte Spill
	movq	%rsi, %rcx
                                        ## kill: def $cl killed $rcx
	movq	-1888(%rbp), %rsi       ## 8-byte Reload
	shrq	%cl, %rsi
	movq	%rsi, -144(%rbp)
	movq	-128(%rbp), %rsi
	movq	(%rsi), %rdi
	movq	-128(%rbp), %rsi
	movl	8(%rsi), %esi
	callq	_fse_mask_lsb64
	movq	-128(%rbp), %rdi
	movq	%rax, (%rdi)
	movq	-144(%rbp), %rax
	movw	%ax, %r8w
	movzwl	%r8w, %edx
	movl	-1876(%rbp), %esi       ## 4-byte Reload
	addl	%edx, %esi
	movw	%si, %r8w
	movq	-152(%rbp), %rax
	movw	%r8w, (%rax)
	movslq	-172(%rbp), %rax
	movq	%rax, -112(%rbp)
	movl	$8, -116(%rbp)
	movl	$8, -120(%rbp)
	movq	-112(%rbp), %rax
	movl	-116(%rbp), %edx
	movl	%edx, %ecx
                                        ## kill: def $cl killed $rcx
	shrq	%cl, %rax
	movl	-120(%rbp), %esi
	movq	%rax, %rdi
	callq	_fse_mask_lsb64
	xorl	%edx, %edx
	movb	%dl, %cl
	movq	%rax, -104(%rbp)
	movq	-104(%rbp), %rax
	movb	%al, %r9b
	movq	-1536(%rbp), %rax
	movl	-1580(%rbp), %edx
	addl	$1, %edx
	movl	%edx, %edx
	movl	%edx, %edi
	movb	%r9b, 7232(%rax,%rdi)
	movq	-1536(%rbp), %rax
	addq	$3136, %rax             ## imm = 0xC40
	leaq	-1574(%rbp), %rdi
	movq	%rdi, -72(%rbp)
	movq	%rax, -80(%rbp)
	leaq	-1552(%rbp), %rax
	movq	%rax, -88(%rbp)
	movq	-80(%rbp), %rax
	movq	-72(%rbp), %rdi
	movzwl	(%rdi), %edx
	movl	%edx, %edi
	movl	(%rax,%rdi,4), %edx
	movl	%edx, -92(%rbp)
	movl	-92(%rbp), %edx
	sarl	$16, %edx
	movw	%dx, %r8w
	movzwl	%r8w, %edx
	movq	-88(%rbp), %rax
	movl	-92(%rbp), %esi
	andl	$255, %esi
	movq	%rax, -48(%rbp)
	movl	%esi, -52(%rbp)
	cmpl	$0, -52(%rbp)
	movl	%edx, -1892(%rbp)       ## 4-byte Spill
	movb	%cl, -1893(%rbp)        ## 1-byte Spill
	jl	LBB0_83
## %bb.82:                              ##   in Loop: Header=BB0_61 Depth=2
	movl	-52(%rbp), %eax
	movq	-48(%rbp), %rcx
	cmpl	8(%rcx), %eax
	setle	%dl
	movb	%dl, -1893(%rbp)        ## 1-byte Spill
LBB0_83:                                ##   in Loop: Header=BB0_61 Depth=2
	movb	-1893(%rbp), %al        ## 1-byte Reload
	xorb	$-1, %al
	testb	$1, %al
	jne	LBB0_84
	jmp	LBB0_85
LBB0_84:
	leaq	L___func__.fse_in_pull64(%rip), %rdi
	leaq	L_.str.2(%rip), %rsi
	leaq	L_.str.5(%rip), %rcx
	movl	$408, %edx              ## imm = 0x198
	callq	___assert_rtn
LBB0_85:                                ##   in Loop: Header=BB0_61 Depth=2
	movl	-52(%rbp), %eax
	movq	-48(%rbp), %rcx
	movl	8(%rcx), %edx
	subl	%eax, %edx
	movl	%edx, 8(%rcx)
	movq	-48(%rbp), %rcx
	movq	(%rcx), %rcx
	movq	-48(%rbp), %rsi
	movl	8(%rsi), %eax
	movl	%eax, %esi
	movq	%rcx, -1904(%rbp)       ## 8-byte Spill
	movq	%rsi, %rcx
                                        ## kill: def $cl killed $rcx
	movq	-1904(%rbp), %rsi       ## 8-byte Reload
	shrq	%cl, %rsi
	movq	%rsi, -64(%rbp)
	movq	-48(%rbp), %rsi
	movq	(%rsi), %rdi
	movq	-48(%rbp), %rsi
	movl	8(%rsi), %esi
	callq	_fse_mask_lsb64
	movq	-48(%rbp), %rdi
	movq	%rax, (%rdi)
	movq	-64(%rbp), %rax
	movw	%ax, %r8w
	movzwl	%r8w, %edx
	movl	-1892(%rbp), %esi       ## 4-byte Reload
	addl	%edx, %esi
	movw	%si, %r8w
	movq	-72(%rbp), %rax
	movw	%r8w, (%rax)
	movslq	-92(%rbp), %rax
	movq	%rax, -32(%rbp)
	movl	$8, -36(%rbp)
	movl	$8, -40(%rbp)
	movq	-32(%rbp), %rax
	movl	-36(%rbp), %edx
	movl	%edx, %ecx
                                        ## kill: def $cl killed $rcx
	shrq	%cl, %rax
	movl	-40(%rbp), %esi
	movq	%rax, %rdi
	callq	_fse_mask_lsb64
	xorl	%edx, %edx
	movb	%dl, %cl
	movq	%rax, -24(%rbp)
	movq	-24(%rbp), %rax
	movb	%al, %r9b
	movq	-1536(%rbp), %rax
	movl	-1580(%rbp), %edx
	addl	$2, %edx
	movl	%edx, %edx
	movl	%edx, %edi
	movb	%r9b, 7232(%rax,%rdi)
	movq	-1536(%rbp), %rax
	addq	$3136, %rax             ## imm = 0xC40
	leaq	-1576(%rbp), %rdi
	movq	%rdi, -576(%rbp)
	movq	%rax, -584(%rbp)
	leaq	-1552(%rbp), %rax
	movq	%rax, -592(%rbp)
	movq	-584(%rbp), %rax
	movq	-576(%rbp), %rdi
	movzwl	(%rdi), %edx
	movl	%edx, %edi
	movl	(%rax,%rdi,4), %edx
	movl	%edx, -596(%rbp)
	movl	-596(%rbp), %edx
	sarl	$16, %edx
	movw	%dx, %r8w
	movzwl	%r8w, %edx
	movq	-592(%rbp), %rax
	movl	-596(%rbp), %esi
	andl	$255, %esi
	movq	%rax, -552(%rbp)
	movl	%esi, -556(%rbp)
	cmpl	$0, -556(%rbp)
	movl	%edx, -1908(%rbp)       ## 4-byte Spill
	movb	%cl, -1909(%rbp)        ## 1-byte Spill
	jl	LBB0_87
## %bb.86:                              ##   in Loop: Header=BB0_61 Depth=2
	movl	-556(%rbp), %eax
	movq	-552(%rbp), %rcx
	cmpl	8(%rcx), %eax
	setle	%dl
	movb	%dl, -1909(%rbp)        ## 1-byte Spill
LBB0_87:                                ##   in Loop: Header=BB0_61 Depth=2
	movb	-1909(%rbp), %al        ## 1-byte Reload
	xorb	$-1, %al
	testb	$1, %al
	jne	LBB0_88
	jmp	LBB0_89
LBB0_88:
	leaq	L___func__.fse_in_pull64(%rip), %rdi
	leaq	L_.str.2(%rip), %rsi
	leaq	L_.str.5(%rip), %rcx
	movl	$408, %edx              ## imm = 0x198
	callq	___assert_rtn
LBB0_89:                                ##   in Loop: Header=BB0_61 Depth=2
	movl	-556(%rbp), %eax
	movq	-552(%rbp), %rcx
	movl	8(%rcx), %edx
	subl	%eax, %edx
	movl	%edx, 8(%rcx)
	movq	-552(%rbp), %rcx
	movq	(%rcx), %rcx
	movq	-552(%rbp), %rsi
	movl	8(%rsi), %eax
	movl	%eax, %esi
	movq	%rcx, -1920(%rbp)       ## 8-byte Spill
	movq	%rsi, %rcx
                                        ## kill: def $cl killed $rcx
	movq	-1920(%rbp), %rsi       ## 8-byte Reload
	shrq	%cl, %rsi
	movq	%rsi, -568(%rbp)
	movq	-552(%rbp), %rsi
	movq	(%rsi), %rdi
	movq	-552(%rbp), %rsi
	movl	8(%rsi), %esi
	callq	_fse_mask_lsb64
	movq	-552(%rbp), %rdi
	movq	%rax, (%rdi)
	movq	-568(%rbp), %rax
	movw	%ax, %r8w
	movzwl	%r8w, %edx
	movl	-1908(%rbp), %esi       ## 4-byte Reload
	addl	%edx, %esi
	movw	%si, %r8w
	movq	-576(%rbp), %rax
	movw	%r8w, (%rax)
	movslq	-596(%rbp), %rax
	movq	%rax, -536(%rbp)
	movl	$8, -540(%rbp)
	movl	$8, -544(%rbp)
	movq	-536(%rbp), %rax
	movl	-540(%rbp), %edx
	movl	%edx, %ecx
                                        ## kill: def $cl killed $rcx
	shrq	%cl, %rax
	movl	-544(%rbp), %esi
	movq	%rax, %rdi
	callq	_fse_mask_lsb64
	movq	%rax, -528(%rbp)
	movq	-528(%rbp), %rax
	movb	%al, %cl
	movq	-1536(%rbp), %rax
	movl	-1580(%rbp), %edx
	addl	$3, %edx
	movl	%edx, %edx
	movl	%edx, %edi
	movb	%cl, 7232(%rax,%rdi)
## %bb.90:                              ##   in Loop: Header=BB0_61 Depth=2
	movl	-1580(%rbp), %eax
	addl	$4, %eax
	movl	%eax, -1580(%rbp)
	jmp	LBB0_61
LBB0_91:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	-1536(%rbp), %rax
	addq	$7232, %rax             ## imm = 0x1C40
	movq	-1536(%rbp), %rcx
	movq	%rax, 8(%rcx)
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	movl	-1480(%rbp), %edx
	movl	%edx, %ecx
	addq	%rcx, %rax
	movq	%rax, -1608(%rbp)
	movl	-1464(%rbp), %edx
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	leaq	-1600(%rbp), %rcx
	movq	%rcx, -640(%rbp)
	movl	%edx, -644(%rbp)
	leaq	-1608(%rbp), %rcx
	movq	%rcx, -656(%rbp)
	movq	%rax, -664(%rbp)
	cmpl	$0, -644(%rbp)
	je	LBB0_95
## %bb.92:                              ##   in Loop: Header=BB0_1 Depth=1
	movq	-656(%rbp), %rax
	movq	(%rax), %rax
	movq	-664(%rbp), %rcx
	addq	$8, %rcx
	cmpq	%rcx, %rax
	jae	LBB0_94
## %bb.93:                              ##   in Loop: Header=BB0_1 Depth=1
	movl	$-1, -632(%rbp)
	jmp	LBB0_103
LBB0_94:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	$-1, %rcx
	movq	-656(%rbp), %rax
	movq	(%rax), %rdx
	addq	$-8, %rdx
	movq	%rdx, (%rax)
	movq	-640(%rbp), %rax
	movq	-656(%rbp), %rdx
	movq	(%rdx), %rsi
	movq	%rax, %rdi
	movl	$8, %edx
	callq	___memcpy_chk
	movl	-644(%rbp), %r8d
	addl	$64, %r8d
	movq	-640(%rbp), %rcx
	movl	%r8d, 8(%rcx)
	movq	%rax, -1928(%rbp)       ## 8-byte Spill
	jmp	LBB0_98
LBB0_95:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	-656(%rbp), %rax
	movq	(%rax), %rax
	movq	-664(%rbp), %rcx
	addq	$7, %rcx
	cmpq	%rcx, %rax
	jae	LBB0_97
## %bb.96:                              ##   in Loop: Header=BB0_1 Depth=1
	movl	$-1, -632(%rbp)
	jmp	LBB0_103
LBB0_97:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	$-1, %rcx
	movq	-656(%rbp), %rax
	movq	(%rax), %rdx
	addq	$-7, %rdx
	movq	%rdx, (%rax)
	movq	-640(%rbp), %rax
	movq	-656(%rbp), %rdx
	movq	(%rdx), %rsi
	movq	%rax, %rdi
	movl	$7, %edx
	callq	___memcpy_chk
	movq	-640(%rbp), %rcx
	movabsq	$72057594037927935, %rdx ## imm = 0xFFFFFFFFFFFFFF
	andq	(%rcx), %rdx
	movq	%rdx, (%rcx)
	movl	-644(%rbp), %r8d
	addl	$56, %r8d
	movq	-640(%rbp), %rcx
	movl	%r8d, 8(%rcx)
	movq	%rax, -1936(%rbp)       ## 8-byte Spill
LBB0_98:                                ##   in Loop: Header=BB0_1 Depth=1
	movq	-640(%rbp), %rax
	cmpl	$56, 8(%rax)
	jl	LBB0_101
## %bb.99:                              ##   in Loop: Header=BB0_1 Depth=1
	movq	-640(%rbp), %rax
	cmpl	$64, 8(%rax)
	jge	LBB0_101
## %bb.100:                             ##   in Loop: Header=BB0_1 Depth=1
	movq	-640(%rbp), %rax
	movq	(%rax), %rax
	movq	-640(%rbp), %rcx
	movl	8(%rcx), %edx
	movl	%edx, %ecx
                                        ## kill: def $cl killed $rcx
	shrq	%cl, %rax
	cmpq	$0, %rax
	je	LBB0_102
LBB0_101:                               ##   in Loop: Header=BB0_1 Depth=1
	movl	$-1, -632(%rbp)
	jmp	LBB0_103
LBB0_102:                               ##   in Loop: Header=BB0_1 Depth=1
	movl	$0, -632(%rbp)
LBB0_103:                               ##   in Loop: Header=BB0_1 Depth=1
	cmpl	$0, -632(%rbp)
	je	LBB0_105
## %bb.104:
	movl	$-3, -696(%rbp)
	jmp	LBB0_145
LBB0_105:                               ##   in Loop: Header=BB0_1 Depth=1
	movw	-1460(%rbp), %ax
	movq	-1536(%rbp), %rcx
	movw	%ax, 52(%rcx)
	movw	-1458(%rbp), %ax
	movq	-1536(%rbp), %rcx
	movw	%ax, 54(%rcx)
	movw	-1456(%rbp), %ax
	movq	-1536(%rbp), %rcx
	movw	%ax, 56(%rcx)
	movq	-1608(%rbp), %rcx
	movq	-704(%rbp), %rdx
	movq	(%rdx), %rdx
	subq	%rdx, %rcx
	movl	%ecx, %esi
	movq	-1536(%rbp), %rcx
	movl	%esi, 48(%rcx)
	movq	-1536(%rbp), %rcx
	movl	$0, 20(%rcx)
	movq	-1536(%rbp), %rcx
	movl	$0, 16(%rcx)
	movq	-1536(%rbp), %rcx
	movl	$-1, 24(%rcx)
	movq	-1536(%rbp), %rcx
	movq	-1600(%rbp), %rdx
	movq	%rdx, 32(%rcx)
	movq	-1592(%rbp), %rdx
	movq	%rdx, 40(%rcx)
	movl	-708(%rbp), %esi
	movq	-704(%rbp), %rcx
	movl	%esi, 52(%rcx)
	jmp	LBB0_144
LBB0_106:
	movl	$-3, -696(%rbp)
	jmp	LBB0_145
LBB0_107:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	addq	$47364, %rax            ## imm = 0xB904
	movq	%rax, -1616(%rbp)
	movq	-1616(%rbp), %rax
	movl	(%rax), %ecx
	movl	%ecx, -1620(%rbp)
	cmpl	$0, -1620(%rbp)
	jne	LBB0_109
## %bb.108:                             ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movl	$0, 52(%rax)
	jmp	LBB0_144
LBB0_109:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	16(%rax), %rax
	movq	-704(%rbp), %rcx
	cmpq	(%rcx), %rax
	ja	LBB0_111
## %bb.110:
	movl	$-1, -696(%rbp)
	jmp	LBB0_145
LBB0_111:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	16(%rax), %rax
	movq	-704(%rbp), %rcx
	movq	(%rcx), %rcx
	subq	%rcx, %rax
	movq	%rax, -1632(%rbp)
	movl	-1620(%rbp), %edx
	movl	%edx, %eax
	cmpq	-1632(%rbp), %rax
	jbe	LBB0_113
## %bb.112:                             ##   in Loop: Header=BB0_1 Depth=1
	movq	-1632(%rbp), %rax
	movl	%eax, %ecx
	movl	%ecx, -1620(%rbp)
LBB0_113:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	40(%rax), %rax
	movq	-704(%rbp), %rcx
	cmpq	24(%rcx), %rax
	ja	LBB0_115
## %bb.114:
	movl	$-2, -696(%rbp)
	jmp	LBB0_145
LBB0_115:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	40(%rax), %rax
	movq	-704(%rbp), %rcx
	movq	24(%rcx), %rcx
	subq	%rcx, %rax
	movq	%rax, -1640(%rbp)
	movl	-1620(%rbp), %edx
	movl	%edx, %eax
	cmpq	-1640(%rbp), %rax
	jbe	LBB0_117
## %bb.116:                             ##   in Loop: Header=BB0_1 Depth=1
	movq	-1640(%rbp), %rax
	movl	%eax, %ecx
	movl	%ecx, -1620(%rbp)
LBB0_117:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	$-1, %rcx
	movq	-704(%rbp), %rax
	movq	24(%rax), %rdi
	movq	-704(%rbp), %rax
	movq	(%rax), %rsi
	movl	-1620(%rbp), %edx
                                        ## kill: def $rdx killed $edx
	callq	___memcpy_chk
	movl	-1620(%rbp), %r8d
	movq	-704(%rbp), %rcx
	movq	(%rcx), %rdx
	movl	%r8d, %r8d
	movl	%r8d, %esi
	addq	%rsi, %rdx
	movq	%rdx, (%rcx)
	movl	-1620(%rbp), %r8d
	movq	-704(%rbp), %rcx
	movq	24(%rcx), %rdx
	movl	%r8d, %r8d
	movl	%r8d, %esi
	addq	%rsi, %rdx
	movq	%rdx, 24(%rcx)
	movl	-1620(%rbp), %r8d
	movq	-1616(%rbp), %rcx
	movl	(%rcx), %r9d
	subl	%r8d, %r9d
	movl	%r9d, (%rcx)
	movq	%rax, -1944(%rbp)       ## 8-byte Spill
	jmp	LBB0_144
LBB0_118:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	addq	$56, %rax
	movq	%rax, -1648(%rbp)
	movq	-704(%rbp), %rax
	movq	16(%rax), %rax
	movq	-704(%rbp), %rcx
	cmpq	(%rcx), %rax
	jbe	LBB0_120
## %bb.119:                             ##   in Loop: Header=BB0_1 Depth=1
	movq	-1648(%rbp), %rax
	movl	4(%rax), %ecx
	movl	%ecx, %eax
	movq	-704(%rbp), %rdx
	movq	16(%rdx), %rdx
	movq	-704(%rbp), %rsi
	movq	(%rsi), %rsi
	subq	%rsi, %rdx
	cmpq	%rdx, %rax
	jbe	LBB0_121
LBB0_120:
	movl	$-1, -696(%rbp)
	jmp	LBB0_145
LBB0_121:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rdi
	callq	_lzfse_decode_lmd
	movl	%eax, -1652(%rbp)
	cmpl	$0, -1652(%rbp)
	je	LBB0_123
## %bb.122:
	movl	-1652(%rbp), %eax
	movl	%eax, -696(%rbp)
	jmp	LBB0_145
LBB0_123:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movl	$0, 52(%rax)
	movq	-1648(%rbp), %rax
	movl	4(%rax), %ecx
	movq	-704(%rbp), %rax
	movq	(%rax), %rdx
	movl	%ecx, %ecx
	movl	%ecx, %esi
	addq	%rsi, %rdx
	movq	%rdx, (%rax)
	jmp	LBB0_144
LBB0_124:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	addq	$47352, %rax            ## imm = 0xB8F8
	movq	%rax, -1664(%rbp)
	movq	-1664(%rbp), %rax
	cmpl	$0, 4(%rax)
	jbe	LBB0_127
## %bb.125:                             ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	16(%rax), %rax
	movq	-704(%rbp), %rcx
	cmpq	(%rcx), %rax
	ja	LBB0_127
## %bb.126:
	movl	$-1, -696(%rbp)
	jmp	LBB0_145
LBB0_127:                               ##   in Loop: Header=BB0_1 Depth=1
	xorl	%esi, %esi
	leaq	-1752(%rbp), %rax
	movq	%rax, %rdi
	movl	$88, %edx
	callq	_memset
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -1752(%rbp)
	movq	-704(%rbp), %rax
	movq	16(%rax), %rax
	movq	%rax, -1744(%rbp)
	movq	-1744(%rbp), %rax
	movq	-704(%rbp), %rdx
	movq	(%rdx), %rdx
	subq	%rdx, %rax
	movq	-1664(%rbp), %rdx
	movl	4(%rdx), %esi
	movl	%esi, %edx
	cmpq	%rdx, %rax
	jle	LBB0_129
## %bb.128:                             ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	(%rax), %rax
	movq	-1664(%rbp), %rcx
	movl	4(%rcx), %edx
	movl	%edx, %ecx
	addq	%rcx, %rax
	movq	%rax, -1744(%rbp)
LBB0_129:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	32(%rax), %rax
	movq	%rax, -1728(%rbp)
	movq	-704(%rbp), %rax
	movq	24(%rax), %rax
	movq	%rax, -1736(%rbp)
	movq	-704(%rbp), %rax
	movq	40(%rax), %rax
	movq	%rax, -1720(%rbp)
	movq	-1720(%rbp), %rax
	movq	-704(%rbp), %rcx
	movq	24(%rcx), %rcx
	subq	%rcx, %rax
	movq	-1664(%rbp), %rcx
	movl	(%rcx), %edx
	movl	%edx, %ecx
	cmpq	%rcx, %rax
	jle	LBB0_131
## %bb.130:                             ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movq	24(%rax), %rax
	movq	-1664(%rbp), %rcx
	movl	(%rcx), %edx
	movl	%edx, %ecx
	addq	%rcx, %rax
	movq	%rax, -1720(%rbp)
LBB0_131:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-1664(%rbp), %rax
	movl	8(%rax), %ecx
	movl	%ecx, %eax
	movq	%rax, -1680(%rbp)
	movl	$0, -1672(%rbp)
	leaq	-1752(%rbp), %rdi
	callq	_lzvn_decode
	movq	-1752(%rbp), %rax
	movq	-704(%rbp), %rdi
	movq	(%rdi), %rdi
	subq	%rdi, %rax
	movq	%rax, -1760(%rbp)
	movq	-1736(%rbp), %rax
	movq	-704(%rbp), %rdi
	movq	24(%rdi), %rdi
	subq	%rdi, %rax
	movq	%rax, -1768(%rbp)
	movq	-1760(%rbp), %rax
	movq	-1664(%rbp), %rdi
	movl	4(%rdi), %ecx
	movl	%ecx, %edi
	cmpq	%rdi, %rax
	ja	LBB0_133
## %bb.132:                             ##   in Loop: Header=BB0_1 Depth=1
	movq	-1768(%rbp), %rax
	movq	-1664(%rbp), %rcx
	movl	(%rcx), %edx
	movl	%edx, %ecx
	cmpq	%rcx, %rax
	jbe	LBB0_134
LBB0_133:
	movl	$-3, -696(%rbp)
	jmp	LBB0_145
LBB0_134:                               ##   in Loop: Header=BB0_1 Depth=1
	movq	-1752(%rbp), %rax
	movq	-704(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-1736(%rbp), %rax
	movq	-704(%rbp), %rcx
	movq	%rax, 24(%rcx)
	movq	-1760(%rbp), %rax
	movl	%eax, %edx
	movq	-1664(%rbp), %rax
	movl	4(%rax), %esi
	subl	%edx, %esi
	movl	%esi, 4(%rax)
	movq	-1768(%rbp), %rax
	movl	%eax, %edx
	movq	-1664(%rbp), %rax
	movl	(%rax), %esi
	subl	%edx, %esi
	movl	%esi, (%rax)
	movq	-1680(%rbp), %rax
	movl	%eax, %edx
	movq	-1664(%rbp), %rax
	movl	%edx, 8(%rax)
	movq	-1664(%rbp), %rax
	cmpl	$0, 4(%rax)
	jne	LBB0_138
## %bb.135:                             ##   in Loop: Header=BB0_1 Depth=1
	movq	-1664(%rbp), %rax
	cmpl	$0, (%rax)
	jne	LBB0_138
## %bb.136:                             ##   in Loop: Header=BB0_1 Depth=1
	cmpl	$0, -1672(%rbp)
	je	LBB0_138
## %bb.137:                             ##   in Loop: Header=BB0_1 Depth=1
	movq	-704(%rbp), %rax
	movl	$0, 52(%rax)
	jmp	LBB0_144
LBB0_138:
	movq	-1664(%rbp), %rax
	cmpl	$0, 4(%rax)
	je	LBB0_141
## %bb.139:
	movq	-1664(%rbp), %rax
	cmpl	$0, (%rax)
	je	LBB0_141
## %bb.140:
	cmpl	$0, -1672(%rbp)
	je	LBB0_142
LBB0_141:
	movl	$-3, -696(%rbp)
	jmp	LBB0_145
LBB0_142:
	movl	$-2, -696(%rbp)
	jmp	LBB0_145
LBB0_143:
	movl	$-3, -696(%rbp)
	jmp	LBB0_145
LBB0_144:                               ##   in Loop: Header=BB0_1 Depth=1
	jmp	LBB0_1
LBB0_145:
	movl	-696(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -1948(%rbp)       ## 4-byte Spill
	jne	LBB0_147
## %bb.146:
	movl	-1948(%rbp), %eax       ## 4-byte Reload
	addq	$1952, %rsp             ## imm = 0x7A0
	popq	%rbp
	retq
LBB0_147:
	callq	___stack_chk_fail
	ud2
	.cfi_endproc
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function lzfse_decode_v2_header_size
_lzfse_decode_v2_header_size:           ## @lzfse_decode_v2_header_size
	.cfi_startproc
## %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	subq	$16, %rsp
	xorl	%esi, %esi
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rdi
	movq	24(%rdi), %rdi
	movl	$32, %edx
	callq	_get_field
	addq	$16, %rsp
	popq	%rbp
	retq
	.cfi_endproc
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function lzfse_decode_v1
_lzfse_decode_v1:                       ## @lzfse_decode_v1
	.cfi_startproc
## %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	subq	$112, %rsp
	xorl	%eax, %eax
	movq	$-1, %rcx
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
	movq	-16(%rbp), %rsi
	movq	%rsi, %rdi
	movl	%eax, %esi
	movl	$772, %edx              ## imm = 0x304
	callq	___memset_chk
	xorl	%esi, %esi
	movq	-24(%rbp), %rcx
	movq	8(%rcx), %rcx
	movq	%rcx, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	16(%rcx), %rcx
	movq	%rcx, -40(%rbp)
	movq	-24(%rbp), %rcx
	movq	24(%rcx), %rcx
	movq	%rcx, -48(%rbp)
	movq	-16(%rbp), %rcx
	movl	$829978210, (%rcx)      ## imm = 0x31787662
	movq	-24(%rbp), %rcx
	movl	4(%rcx), %r8d
	movq	-16(%rbp), %rcx
	movl	%r8d, 4(%rcx)
	movq	-32(%rbp), %rdi
	movl	$20, %edx
	movq	%rax, -96(%rbp)         ## 8-byte Spill
	callq	_get_field
	movq	-16(%rbp), %rcx
	movl	%eax, 12(%rcx)
	movq	-32(%rbp), %rdi
	movl	$20, %eax
	movl	%eax, %esi
	movl	%eax, %edx
	callq	_get_field
	movq	-16(%rbp), %rcx
	movl	%eax, 20(%rcx)
	movq	-32(%rbp), %rdi
	movl	$60, %esi
	movl	$3, %edx
	callq	_get_field
	xorl	%esi, %esi
	subl	$7, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, 28(%rcx)
	movq	-40(%rbp), %rdi
	movl	$10, %edx
	callq	_get_field
	movw	%ax, %r9w
	movq	-16(%rbp), %rcx
	movw	%r9w, 32(%rcx)
	movq	-40(%rbp), %rdi
	movl	$10, %eax
	movl	%eax, %esi
	movl	%eax, %edx
	callq	_get_field
	movw	%ax, %r9w
	movq	-16(%rbp), %rcx
	movw	%r9w, 34(%rcx)
	movq	-40(%rbp), %rdi
	movl	$20, %esi
	movl	$10, %edx
	callq	_get_field
	movw	%ax, %r9w
	movq	-16(%rbp), %rcx
	movw	%r9w, 36(%rcx)
	movq	-40(%rbp), %rdi
	movl	$30, %esi
	movl	$10, %edx
	callq	_get_field
	movw	%ax, %r9w
	movq	-16(%rbp), %rcx
	movw	%r9w, 38(%rcx)
	movq	-32(%rbp), %rdi
	movl	$40, %esi
	movl	$20, %edx
	callq	_get_field
	movq	-16(%rbp), %rcx
	movl	%eax, 16(%rcx)
	movq	-40(%rbp), %rdi
	movl	$40, %esi
	movl	$20, %edx
	callq	_get_field
	movq	-16(%rbp), %rcx
	movl	%eax, 24(%rcx)
	movq	-40(%rbp), %rdi
	movl	$60, %esi
	movl	$3, %edx
	callq	_get_field
	subl	$7, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, 40(%rcx)
	movq	-48(%rbp), %rdi
	movl	$32, %esi
	movl	$10, %edx
	callq	_get_field
	movw	%ax, %r9w
	movq	-16(%rbp), %rcx
	movw	%r9w, 44(%rcx)
	movq	-48(%rbp), %rdi
	movl	$42, %esi
	movl	$10, %edx
	callq	_get_field
	movw	%ax, %r9w
	movq	-16(%rbp), %rcx
	movw	%r9w, 46(%rcx)
	movq	-48(%rbp), %rdi
	movl	$52, %esi
	movl	$10, %edx
	callq	_get_field
	xorl	%esi, %esi
	movw	%ax, %r9w
	movq	-16(%rbp), %rcx
	movw	%r9w, 48(%rcx)
	movq	-16(%rbp), %rcx
	movl	20(%rcx), %eax
	movq	-16(%rbp), %rcx
	addl	24(%rcx), %eax
	movq	-16(%rbp), %rcx
	movl	%eax, 8(%rcx)
	movq	-16(%rbp), %rcx
	addq	$50, %rcx
	movq	%rcx, -56(%rbp)
	movq	-24(%rbp), %rcx
	addq	$32, %rcx
	movq	%rcx, -64(%rbp)
	movq	-24(%rbp), %rcx
	movq	-48(%rbp), %rdi
	movl	$32, %edx
	movq	%rcx, -104(%rbp)        ## 8-byte Spill
	callq	_get_field
	movl	%eax, %eax
	movl	%eax, %ecx
	movq	-104(%rbp), %rdi        ## 8-byte Reload
	addq	%rcx, %rdi
	movq	%rdi, -72(%rbp)
	movl	$0, -76(%rbp)
	movl	$0, -80(%rbp)
	movq	-72(%rbp), %rcx
	cmpq	-64(%rbp), %rcx
	jne	LBB2_2
## %bb.1:
	movl	$0, -4(%rbp)
	jmp	LBB2_17
LBB2_2:
	movl	$0, -84(%rbp)
LBB2_3:                                 ## =>This Loop Header: Depth=1
                                        ##     Child Loop BB2_5 Depth 2
	cmpl	$360, -84(%rbp)         ## imm = 0x168
	jge	LBB2_13
## %bb.4:                               ##   in Loop: Header=BB2_3 Depth=1
	jmp	LBB2_5
LBB2_5:                                 ##   Parent Loop BB2_3 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	xorl	%eax, %eax
	movb	%al, %cl
	movq	-64(%rbp), %rdx
	cmpq	-72(%rbp), %rdx
	movb	%cl, -105(%rbp)         ## 1-byte Spill
	jae	LBB2_7
## %bb.6:                               ##   in Loop: Header=BB2_5 Depth=2
	movl	-80(%rbp), %eax
	addl	$8, %eax
	cmpl	$32, %eax
	setle	%cl
	movb	%cl, -105(%rbp)         ## 1-byte Spill
LBB2_7:                                 ##   in Loop: Header=BB2_5 Depth=2
	movb	-105(%rbp), %al         ## 1-byte Reload
	testb	$1, %al
	jne	LBB2_8
	jmp	LBB2_9
LBB2_8:                                 ##   in Loop: Header=BB2_5 Depth=2
	movq	-64(%rbp), %rax
	movzbl	(%rax), %ecx
	movl	-80(%rbp), %edx
	movl	%ecx, -112(%rbp)        ## 4-byte Spill
	movl	%edx, %ecx
                                        ## kill: def $cl killed $ecx
	movl	-112(%rbp), %edx        ## 4-byte Reload
	shll	%cl, %edx
	orl	-76(%rbp), %edx
	movl	%edx, -76(%rbp)
	movl	-80(%rbp), %edx
	addl	$8, %edx
	movl	%edx, -80(%rbp)
	movq	-64(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -64(%rbp)
	jmp	LBB2_5
LBB2_9:                                 ##   in Loop: Header=BB2_3 Depth=1
	movl	$0, -88(%rbp)
	movl	-76(%rbp), %edi
	leaq	-88(%rbp), %rsi
	callq	_lzfse_decode_v1_freq_value
	movw	%ax, %cx
	movq	-56(%rbp), %rsi
	movslq	-84(%rbp), %rdx
	movw	%cx, (%rsi,%rdx,2)
	movl	-88(%rbp), %eax
	cmpl	-80(%rbp), %eax
	jle	LBB2_11
## %bb.10:
	movl	$-1, -4(%rbp)
	jmp	LBB2_17
LBB2_11:                                ##   in Loop: Header=BB2_3 Depth=1
	movl	-88(%rbp), %ecx
	movl	-76(%rbp), %eax
                                        ## kill: def $cl killed $ecx
	shrl	%cl, %eax
	movl	%eax, -76(%rbp)
	movl	-88(%rbp), %eax
	movl	-80(%rbp), %edx
	subl	%eax, %edx
	movl	%edx, -80(%rbp)
## %bb.12:                              ##   in Loop: Header=BB2_3 Depth=1
	movl	-84(%rbp), %eax
	addl	$1, %eax
	movl	%eax, -84(%rbp)
	jmp	LBB2_3
LBB2_13:
	cmpl	$8, -80(%rbp)
	jge	LBB2_15
## %bb.14:
	movq	-64(%rbp), %rax
	cmpq	-72(%rbp), %rax
	je	LBB2_16
LBB2_15:
	movl	$-1, -4(%rbp)
	jmp	LBB2_17
LBB2_16:
	movl	$0, -4(%rbp)
LBB2_17:
	movl	-4(%rbp), %eax
	addq	$112, %rsp
	popq	%rbp
	retq
	.cfi_endproc
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function lzfse_decode_lmd
_lzfse_decode_lmd:                      ## @lzfse_decode_lmd
	.cfi_startproc
## %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	subq	$480, %rsp              ## imm = 0x1E0
	movq	%rdi, -256(%rbp)
	movq	-256(%rbp), %rdi
	addq	$56, %rdi
	movq	%rdi, -264(%rbp)
	movq	-264(%rbp), %rdi
	movw	52(%rdi), %ax
	movw	%ax, -266(%rbp)
	movq	-264(%rbp), %rdi
	movw	54(%rdi), %ax
	movw	%ax, -268(%rbp)
	movq	-264(%rbp), %rdi
	movw	56(%rdi), %ax
	movw	%ax, -270(%rbp)
	movq	-264(%rbp), %rdi
	movq	32(%rdi), %rcx
	movq	%rcx, -288(%rbp)
	movq	40(%rdi), %rcx
	movq	%rcx, -280(%rbp)
	movq	-256(%rbp), %rcx
	movq	8(%rcx), %rcx
	movq	%rcx, -296(%rbp)
	movq	-256(%rbp), %rcx
	movq	(%rcx), %rcx
	movq	-264(%rbp), %rdi
	movl	48(%rdi), %edx
	movl	%edx, %edi
	addq	%rdi, %rcx
	movq	%rcx, -304(%rbp)
	movq	-264(%rbp), %rcx
	movq	8(%rcx), %rcx
	movq	%rcx, -312(%rbp)
	movq	-256(%rbp), %rcx
	movq	24(%rcx), %rcx
	movq	%rcx, -320(%rbp)
	movq	-264(%rbp), %rcx
	movl	(%rcx), %edx
	movl	%edx, -324(%rbp)
	movq	-264(%rbp), %rcx
	movl	16(%rcx), %edx
	movl	%edx, -328(%rbp)
	movq	-264(%rbp), %rcx
	movl	20(%rcx), %edx
	movl	%edx, -332(%rbp)
	movq	-264(%rbp), %rcx
	movl	24(%rcx), %edx
	movl	%edx, -336(%rbp)
	movzwl	-266(%rbp), %edx
	cmpl	$64, %edx
	setl	%sil
	xorb	$-1, %sil
	andb	$1, %sil
	movzbl	%sil, %edx
	movslq	%edx, %rcx
	cmpq	$0, %rcx
	je	LBB3_2
## %bb.1:
	leaq	L___func__.lzfse_decode_lmd(%rip), %rdi
	leaq	L_.str(%rip), %rsi
	leaq	L_.str.6(%rip), %rcx
	movl	$171, %edx
	callq	___assert_rtn
LBB3_2:
	jmp	LBB3_3
LBB3_3:
	movzwl	-268(%rbp), %eax
	cmpl	$64, %eax
	setl	%cl
	xorb	$-1, %cl
	andb	$1, %cl
	movzbl	%cl, %eax
	movslq	%eax, %rdx
	cmpq	$0, %rdx
	je	LBB3_5
## %bb.4:
	leaq	L___func__.lzfse_decode_lmd(%rip), %rdi
	leaq	L_.str(%rip), %rsi
	leaq	L_.str.7(%rip), %rcx
	movl	$172, %edx
	callq	___assert_rtn
LBB3_5:
	jmp	LBB3_6
LBB3_6:
	movzwl	-270(%rbp), %eax
	cmpl	$256, %eax              ## imm = 0x100
	setl	%cl
	xorb	$-1, %cl
	andb	$1, %cl
	movzbl	%cl, %eax
	movslq	%eax, %rdx
	cmpq	$0, %rdx
	je	LBB3_8
## %bb.7:
	leaq	L___func__.lzfse_decode_lmd(%rip), %rdi
	leaq	L_.str(%rip), %rsi
	leaq	L_.str.8(%rip), %rcx
	movl	$173, %edx
	callq	___assert_rtn
LBB3_8:
	jmp	LBB3_9
LBB3_9:
	movq	-256(%rbp), %rax
	movq	40(%rax), %rax
	movq	-320(%rbp), %rcx
	subq	%rcx, %rax
	subq	$32, %rax
	movq	%rax, -344(%rbp)
	cmpl	$0, -328(%rbp)
	jne	LBB3_11
## %bb.10:
	cmpl	$0, -332(%rbp)
	je	LBB3_12
LBB3_11:
	jmp	LBB3_56
LBB3_12:
	jmp	LBB3_13
LBB3_13:
	cmpl	$0, -324(%rbp)
	jbe	LBB3_93
## %bb.14:
	xorl	%eax, %eax
	movl	%eax, %ecx
	movq	-296(%rbp), %rdx
	leaq	-288(%rbp), %rsi
	movq	%rsi, -200(%rbp)
	leaq	-304(%rbp), %rsi
	movq	%rsi, -208(%rbp)
	movq	%rdx, -216(%rbp)
	movq	-200(%rbp), %rdx
	movl	$63, %eax
	subl	8(%rdx), %eax
	andl	$-8, %eax
	movl	%eax, -220(%rbp)
	movq	-208(%rbp), %rdx
	movq	(%rdx), %rdx
	movl	-220(%rbp), %eax
	sarl	$3, %eax
	movslq	%eax, %rsi
	subq	%rsi, %rcx
	addq	%rcx, %rdx
	movq	%rdx, -232(%rbp)
	movq	-232(%rbp), %rcx
	cmpq	-216(%rbp), %rcx
	jae	LBB3_16
## %bb.15:
	movl	$-1, -192(%rbp)
	jmp	LBB3_23
LBB3_16:
	movq	-232(%rbp), %rax
	movq	-208(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-232(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -240(%rbp)
	movq	-200(%rbp), %rax
	movq	(%rax), %rax
	movl	-220(%rbp), %edx
	movl	%edx, %ecx
                                        ## kill: def $cl killed $rcx
	shlq	%cl, %rax
	movq	-240(%rbp), %rdi
	movl	-220(%rbp), %esi
	movq	%rax, -400(%rbp)        ## 8-byte Spill
	callq	_fse_mask_lsb64
	xorl	%edx, %edx
	movb	%dl, %cl
	movq	-400(%rbp), %rdi        ## 8-byte Reload
	orq	%rax, %rdi
	movq	-200(%rbp), %rax
	movq	%rdi, (%rax)
	movl	-220(%rbp), %edx
	movq	-200(%rbp), %rax
	addl	8(%rax), %edx
	movl	%edx, 8(%rax)
	movq	-200(%rbp), %rax
	cmpl	$56, 8(%rax)
	movb	%cl, -401(%rbp)         ## 1-byte Spill
	jl	LBB3_18
## %bb.17:
	movq	-200(%rbp), %rax
	cmpl	$64, 8(%rax)
	setl	%cl
	movb	%cl, -401(%rbp)         ## 1-byte Spill
LBB3_18:
	movb	-401(%rbp), %al         ## 1-byte Reload
	xorb	$-1, %al
	testb	$1, %al
	jne	LBB3_19
	jmp	LBB3_20
LBB3_19:
	leaq	L___func__.fse_in_checked_flush64(%rip), %rdi
	leaq	L_.str.2(%rip), %rsi
	leaq	L_.str.3(%rip), %rcx
	movl	$376, %edx              ## imm = 0x178
	callq	___assert_rtn
LBB3_20:
	movq	-200(%rbp), %rax
	movq	(%rax), %rax
	movq	-200(%rbp), %rcx
	movl	8(%rcx), %edx
	movl	%edx, %ecx
                                        ## kill: def $cl killed $rcx
	shrq	%cl, %rax
	cmpq	$0, %rax
	sete	%cl
	xorb	$-1, %cl
	testb	$1, %cl
	jne	LBB3_21
	jmp	LBB3_22
LBB3_21:
	leaq	L___func__.fse_in_checked_flush64(%rip), %rdi
	leaq	L_.str.2(%rip), %rsi
	leaq	L_.str.4(%rip), %rcx
	movl	$376, %edx              ## imm = 0x178
	callq	___assert_rtn
LBB3_22:
	movl	$0, -192(%rbp)
LBB3_23:
	movl	-192(%rbp), %eax
	movl	%eax, -348(%rbp)
	cmpl	$0, -348(%rbp)
	je	LBB3_25
## %bb.24:
	movl	$-3, -244(%rbp)
	jmp	LBB3_94
LBB3_25:
	xorl	%eax, %eax
	movb	%al, %cl
	movq	-264(%rbp), %rdx
	addq	$64, %rdx
	leaq	-266(%rbp), %rsi
	movq	%rsi, -160(%rbp)
	movq	%rdx, -168(%rbp)
	leaq	-288(%rbp), %rdx
	movq	%rdx, -176(%rbp)
	movq	-168(%rbp), %rdx
	movq	-160(%rbp), %rsi
	movzwl	(%rsi), %eax
	movl	%eax, %esi
	movq	(%rdx,%rsi,8), %rdx
	movq	%rdx, -184(%rbp)
	movq	-176(%rbp), %rdx
	movzbl	-184(%rbp), %eax
	movq	%rdx, -136(%rbp)
	movl	%eax, -140(%rbp)
	cmpl	$0, -140(%rbp)
	movb	%cl, -402(%rbp)         ## 1-byte Spill
	jl	LBB3_27
## %bb.26:
	movl	-140(%rbp), %eax
	movq	-136(%rbp), %rcx
	cmpl	8(%rcx), %eax
	setle	%dl
	movb	%dl, -402(%rbp)         ## 1-byte Spill
LBB3_27:
	movb	-402(%rbp), %al         ## 1-byte Reload
	xorb	$-1, %al
	testb	$1, %al
	jne	LBB3_28
	jmp	LBB3_29
LBB3_28:
	leaq	L___func__.fse_in_pull64(%rip), %rdi
	leaq	L_.str.2(%rip), %rsi
	leaq	L_.str.5(%rip), %rcx
	movl	$408, %edx              ## imm = 0x198
	callq	___assert_rtn
LBB3_29:
	movl	-140(%rbp), %eax
	movq	-136(%rbp), %rcx
	movl	8(%rcx), %edx
	subl	%eax, %edx
	movl	%edx, 8(%rcx)
	movq	-136(%rbp), %rcx
	movq	(%rcx), %rcx
	movq	-136(%rbp), %rsi
	movl	8(%rsi), %eax
	movl	%eax, %esi
	movq	%rcx, -416(%rbp)        ## 8-byte Spill
	movq	%rsi, %rcx
                                        ## kill: def $cl killed $rcx
	movq	-416(%rbp), %rsi        ## 8-byte Reload
	shrq	%cl, %rsi
	movq	%rsi, -152(%rbp)
	movq	-136(%rbp), %rsi
	movq	(%rsi), %rdi
	movq	-136(%rbp), %rsi
	movl	8(%rsi), %esi
	callq	_fse_mask_lsb64
	movq	-136(%rbp), %rdi
	movq	%rax, (%rdi)
	movq	-152(%rbp), %rax
	movl	%eax, %edx
	movl	%edx, -188(%rbp)
	movswl	-182(%rbp), %edx
	movl	-188(%rbp), %esi
	movzbl	-183(%rbp), %ecx
                                        ## kill: def $cl killed $ecx
	shrl	%cl, %esi
	addl	%esi, %edx
	movw	%dx, %r8w
	movq	-160(%rbp), %rax
	movw	%r8w, (%rax)
	movslq	-180(%rbp), %rax
	movl	-188(%rbp), %edx
	movl	%edx, %edi
	movzbl	-183(%rbp), %esi
	movq	%rax, -424(%rbp)        ## 8-byte Spill
	callq	_fse_mask_lsb64
	movq	-424(%rbp), %rdi        ## 8-byte Reload
	addq	%rax, %rdi
	movl	%edi, %edx
	movl	%edx, -328(%rbp)
	movzwl	-266(%rbp), %edx
	cmpl	$64, %edx
	setl	%cl
	xorb	$-1, %cl
	andb	$1, %cl
	movzbl	%cl, %edx
	movslq	%edx, %rax
	cmpq	$0, %rax
	je	LBB3_31
## %bb.30:
	leaq	L___func__.lzfse_decode_lmd(%rip), %rdi
	leaq	L_.str(%rip), %rsi
	leaq	L_.str.6(%rip), %rcx
	movl	$198, %edx
	callq	___assert_rtn
LBB3_31:
	jmp	LBB3_32
LBB3_32:
	movq	-312(%rbp), %rax
	movslq	-328(%rbp), %rcx
	addq	%rcx, %rax
	movq	-264(%rbp), %rcx
	addq	$7232, %rcx             ## imm = 0x1C40
	addq	$40000, %rcx            ## imm = 0x9C40
	addq	$64, %rcx
	cmpq	%rcx, %rax
	jb	LBB3_34
## %bb.33:
	movl	$-3, -244(%rbp)
	jmp	LBB3_94
LBB3_34:
	movl	$0, -348(%rbp)
	cmpl	$0, -348(%rbp)
	je	LBB3_36
## %bb.35:
	movl	$-3, -244(%rbp)
	jmp	LBB3_94
LBB3_36:
	xorl	%eax, %eax
	movb	%al, %cl
	movq	-264(%rbp), %rdx
	addq	$576, %rdx              ## imm = 0x240
	leaq	-268(%rbp), %rsi
	movq	%rsi, -96(%rbp)
	movq	%rdx, -104(%rbp)
	leaq	-288(%rbp), %rdx
	movq	%rdx, -112(%rbp)
	movq	-104(%rbp), %rdx
	movq	-96(%rbp), %rsi
	movzwl	(%rsi), %eax
	movl	%eax, %esi
	movq	(%rdx,%rsi,8), %rdx
	movq	%rdx, -120(%rbp)
	movq	-112(%rbp), %rdx
	movzbl	-120(%rbp), %eax
	movq	%rdx, -72(%rbp)
	movl	%eax, -76(%rbp)
	cmpl	$0, -76(%rbp)
	movb	%cl, -425(%rbp)         ## 1-byte Spill
	jl	LBB3_38
## %bb.37:
	movl	-76(%rbp), %eax
	movq	-72(%rbp), %rcx
	cmpl	8(%rcx), %eax
	setle	%dl
	movb	%dl, -425(%rbp)         ## 1-byte Spill
LBB3_38:
	movb	-425(%rbp), %al         ## 1-byte Reload
	xorb	$-1, %al
	testb	$1, %al
	jne	LBB3_39
	jmp	LBB3_40
LBB3_39:
	leaq	L___func__.fse_in_pull64(%rip), %rdi
	leaq	L_.str.2(%rip), %rsi
	leaq	L_.str.5(%rip), %rcx
	movl	$408, %edx              ## imm = 0x198
	callq	___assert_rtn
LBB3_40:
	movl	-76(%rbp), %eax
	movq	-72(%rbp), %rcx
	movl	8(%rcx), %edx
	subl	%eax, %edx
	movl	%edx, 8(%rcx)
	movq	-72(%rbp), %rcx
	movq	(%rcx), %rcx
	movq	-72(%rbp), %rsi
	movl	8(%rsi), %eax
	movl	%eax, %esi
	movq	%rcx, -440(%rbp)        ## 8-byte Spill
	movq	%rsi, %rcx
                                        ## kill: def $cl killed $rcx
	movq	-440(%rbp), %rsi        ## 8-byte Reload
	shrq	%cl, %rsi
	movq	%rsi, -88(%rbp)
	movq	-72(%rbp), %rsi
	movq	(%rsi), %rdi
	movq	-72(%rbp), %rsi
	movl	8(%rsi), %esi
	callq	_fse_mask_lsb64
	movq	-72(%rbp), %rdi
	movq	%rax, (%rdi)
	movq	-88(%rbp), %rax
	movl	%eax, %edx
	movl	%edx, -124(%rbp)
	movswl	-118(%rbp), %edx
	movl	-124(%rbp), %esi
	movzbl	-119(%rbp), %ecx
                                        ## kill: def $cl killed $ecx
	shrl	%cl, %esi
	addl	%esi, %edx
	movw	%dx, %r8w
	movq	-96(%rbp), %rax
	movw	%r8w, (%rax)
	movslq	-116(%rbp), %rax
	movl	-124(%rbp), %edx
	movl	%edx, %edi
	movzbl	-119(%rbp), %esi
	movq	%rax, -448(%rbp)        ## 8-byte Spill
	callq	_fse_mask_lsb64
	movq	-448(%rbp), %rdi        ## 8-byte Reload
	addq	%rax, %rdi
	movl	%edi, %edx
	movl	%edx, -332(%rbp)
	movzwl	-268(%rbp), %edx
	cmpl	$64, %edx
	setl	%cl
	xorb	$-1, %cl
	andb	$1, %cl
	movzbl	%cl, %edx
	movslq	%edx, %rax
	cmpq	$0, %rax
	je	LBB3_42
## %bb.41:
	leaq	L___func__.lzfse_decode_lmd(%rip), %rdi
	leaq	L_.str(%rip), %rsi
	leaq	L_.str.7(%rip), %rcx
	movl	$207, %edx
	callq	___assert_rtn
LBB3_42:
	jmp	LBB3_43
LBB3_43:
	movl	$0, -348(%rbp)
	cmpl	$0, -348(%rbp)
	je	LBB3_45
## %bb.44:
	movl	$-3, -244(%rbp)
	jmp	LBB3_94
LBB3_45:
	xorl	%eax, %eax
	movb	%al, %cl
	movq	-264(%rbp), %rdx
	addq	$1088, %rdx             ## imm = 0x440
	leaq	-270(%rbp), %rsi
	movq	%rsi, -32(%rbp)
	movq	%rdx, -40(%rbp)
	leaq	-288(%rbp), %rdx
	movq	%rdx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movzwl	(%rsi), %eax
	movl	%eax, %esi
	movq	(%rdx,%rsi,8), %rdx
	movq	%rdx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movzbl	-56(%rbp), %eax
	movq	%rdx, -8(%rbp)
	movl	%eax, -12(%rbp)
	cmpl	$0, -12(%rbp)
	movb	%cl, -449(%rbp)         ## 1-byte Spill
	jl	LBB3_47
## %bb.46:
	movl	-12(%rbp), %eax
	movq	-8(%rbp), %rcx
	cmpl	8(%rcx), %eax
	setle	%dl
	movb	%dl, -449(%rbp)         ## 1-byte Spill
LBB3_47:
	movb	-449(%rbp), %al         ## 1-byte Reload
	xorb	$-1, %al
	testb	$1, %al
	jne	LBB3_48
	jmp	LBB3_49
LBB3_48:
	leaq	L___func__.fse_in_pull64(%rip), %rdi
	leaq	L_.str.2(%rip), %rsi
	leaq	L_.str.5(%rip), %rcx
	movl	$408, %edx              ## imm = 0x198
	callq	___assert_rtn
LBB3_49:
	movl	-12(%rbp), %eax
	movq	-8(%rbp), %rcx
	movl	8(%rcx), %edx
	subl	%eax, %edx
	movl	%edx, 8(%rcx)
	movq	-8(%rbp), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rsi
	movl	8(%rsi), %eax
	movl	%eax, %esi
	movq	%rcx, -464(%rbp)        ## 8-byte Spill
	movq	%rsi, %rcx
                                        ## kill: def $cl killed $rcx
	movq	-464(%rbp), %rsi        ## 8-byte Reload
	shrq	%cl, %rsi
	movq	%rsi, -24(%rbp)
	movq	-8(%rbp), %rsi
	movq	(%rsi), %rdi
	movq	-8(%rbp), %rsi
	movl	8(%rsi), %esi
	callq	_fse_mask_lsb64
	movq	-8(%rbp), %rdi
	movq	%rax, (%rdi)
	movq	-24(%rbp), %rax
	movl	%eax, %edx
	movl	%edx, -60(%rbp)
	movswl	-54(%rbp), %edx
	movl	-60(%rbp), %esi
	movzbl	-55(%rbp), %ecx
                                        ## kill: def $cl killed $ecx
	shrl	%cl, %esi
	addl	%esi, %edx
	movw	%dx, %r8w
	movq	-32(%rbp), %rax
	movw	%r8w, (%rax)
	movslq	-52(%rbp), %rax
	movl	-60(%rbp), %edx
	movl	%edx, %edi
	movzbl	-55(%rbp), %esi
	movq	%rax, -472(%rbp)        ## 8-byte Spill
	callq	_fse_mask_lsb64
	movq	-472(%rbp), %rdi        ## 8-byte Reload
	addq	%rax, %rdi
	movl	%edi, %edx
	movl	%edx, -352(%rbp)
	movzwl	-270(%rbp), %edx
	cmpl	$256, %edx              ## imm = 0x100
	setl	%cl
	xorb	$-1, %cl
	andb	$1, %cl
	movzbl	%cl, %edx
	movslq	%edx, %rax
	cmpq	$0, %rax
	je	LBB3_51
## %bb.50:
	leaq	L___func__.lzfse_decode_lmd(%rip), %rdi
	leaq	L_.str(%rip), %rsi
	leaq	L_.str.8(%rip), %rcx
	movl	$213, %edx
	callq	___assert_rtn
LBB3_51:
	jmp	LBB3_52
LBB3_52:
	cmpl	$0, -352(%rbp)
	je	LBB3_54
## %bb.53:
	movl	-352(%rbp), %eax
	movl	%eax, -476(%rbp)        ## 4-byte Spill
	jmp	LBB3_55
LBB3_54:
	movl	-336(%rbp), %eax
	movl	%eax, -476(%rbp)        ## 4-byte Spill
LBB3_55:
	movl	-476(%rbp), %eax        ## 4-byte Reload
	movl	%eax, -336(%rbp)
	movl	-324(%rbp), %eax
	addl	$-1, %eax
	movl	%eax, -324(%rbp)
LBB3_56:
	movl	-336(%rbp), %eax
	movl	%eax, %ecx
	movq	-320(%rbp), %rdx
	movslq	-328(%rbp), %rsi
	addq	%rsi, %rdx
	movq	-256(%rbp), %rsi
	movq	32(%rsi), %rsi
	subq	%rsi, %rdx
	cmpq	%rdx, %rcx
	jle	LBB3_58
## %bb.57:
	movl	$-3, -244(%rbp)
	jmp	LBB3_94
LBB3_58:
	movl	-328(%rbp), %eax
	addl	-332(%rbp), %eax
	movslq	%eax, %rcx
	cmpq	-344(%rbp), %rcx
	jg	LBB3_68
## %bb.59:
	movl	-328(%rbp), %eax
	addl	-332(%rbp), %eax
	movslq	%eax, %rcx
	movq	-344(%rbp), %rdx
	subq	%rcx, %rdx
	movq	%rdx, -344(%rbp)
	movq	-320(%rbp), %rdi
	movq	-312(%rbp), %rsi
	movslq	-328(%rbp), %rdx
	callq	_copy
	movl	-328(%rbp), %eax
	movq	-320(%rbp), %rcx
	movslq	%eax, %rdx
	addq	%rdx, %rcx
	movq	%rcx, -320(%rbp)
	movl	-328(%rbp), %eax
	movq	-312(%rbp), %rcx
	movslq	%eax, %rdx
	addq	%rdx, %rcx
	movq	%rcx, -312(%rbp)
	cmpl	$8, -336(%rbp)
	jge	LBB3_61
## %bb.60:
	movl	-336(%rbp), %eax
	cmpl	-332(%rbp), %eax
	jl	LBB3_62
LBB3_61:
	xorl	%eax, %eax
	movl	%eax, %ecx
	movq	-320(%rbp), %rdi
	movq	-320(%rbp), %rdx
	movslq	-336(%rbp), %rsi
	subq	%rsi, %rcx
	addq	%rcx, %rdx
	movslq	-332(%rbp), %rcx
	movq	%rdx, %rsi
	movq	%rcx, %rdx
	callq	_copy
	jmp	LBB3_67
LBB3_62:
	movq	$0, -360(%rbp)
LBB3_63:                                ## =>This Inner Loop Header: Depth=1
	movq	-360(%rbp), %rax
	movslq	-332(%rbp), %rcx
	cmpq	%rcx, %rax
	jae	LBB3_66
## %bb.64:                              ##   in Loop: Header=BB3_63 Depth=1
	movq	-320(%rbp), %rax
	movq	-360(%rbp), %rcx
	movslq	-336(%rbp), %rdx
	subq	%rdx, %rcx
	movb	(%rax,%rcx), %sil
	movq	-320(%rbp), %rax
	movq	-360(%rbp), %rcx
	movb	%sil, (%rax,%rcx)
## %bb.65:                              ##   in Loop: Header=BB3_63 Depth=1
	movq	-360(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -360(%rbp)
	jmp	LBB3_63
LBB3_66:
	jmp	LBB3_67
LBB3_67:
	movl	-332(%rbp), %eax
	movq	-320(%rbp), %rcx
	movslq	%eax, %rdx
	addq	%rdx, %rcx
	movq	%rcx, -320(%rbp)
	jmp	LBB3_92
LBB3_68:
	movq	-344(%rbp), %rax
	addq	$32, %rax
	movq	%rax, -344(%rbp)
	movslq	-328(%rbp), %rax
	cmpq	-344(%rbp), %rax
	jg	LBB3_74
## %bb.69:
	movq	$0, -368(%rbp)
LBB3_70:                                ## =>This Inner Loop Header: Depth=1
	movq	-368(%rbp), %rax
	movslq	-328(%rbp), %rcx
	cmpq	%rcx, %rax
	jae	LBB3_73
## %bb.71:                              ##   in Loop: Header=BB3_70 Depth=1
	movq	-312(%rbp), %rax
	movq	-368(%rbp), %rcx
	movb	(%rax,%rcx), %dl
	movq	-320(%rbp), %rax
	movq	-368(%rbp), %rcx
	movb	%dl, (%rax,%rcx)
## %bb.72:                              ##   in Loop: Header=BB3_70 Depth=1
	movq	-368(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -368(%rbp)
	jmp	LBB3_70
LBB3_73:
	movl	-328(%rbp), %eax
	movq	-320(%rbp), %rcx
	movslq	%eax, %rdx
	addq	%rdx, %rcx
	movq	%rcx, -320(%rbp)
	movl	-328(%rbp), %eax
	movq	-312(%rbp), %rcx
	movslq	%eax, %rdx
	addq	%rdx, %rcx
	movq	%rcx, -312(%rbp)
	movslq	-328(%rbp), %rcx
	movq	-344(%rbp), %rdx
	subq	%rcx, %rdx
	movq	%rdx, -344(%rbp)
	movl	$0, -328(%rbp)
	jmp	LBB3_79
LBB3_74:
	movq	$0, -376(%rbp)
LBB3_75:                                ## =>This Inner Loop Header: Depth=1
	movq	-376(%rbp), %rax
	cmpq	-344(%rbp), %rax
	jae	LBB3_78
## %bb.76:                              ##   in Loop: Header=BB3_75 Depth=1
	movq	-312(%rbp), %rax
	movq	-376(%rbp), %rcx
	movb	(%rax,%rcx), %dl
	movq	-320(%rbp), %rax
	movq	-376(%rbp), %rcx
	movb	%dl, (%rax,%rcx)
## %bb.77:                              ##   in Loop: Header=BB3_75 Depth=1
	movq	-376(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -376(%rbp)
	jmp	LBB3_75
LBB3_78:
	movq	-344(%rbp), %rax
	addq	-320(%rbp), %rax
	movq	%rax, -320(%rbp)
	movq	-344(%rbp), %rax
	addq	-312(%rbp), %rax
	movq	%rax, -312(%rbp)
	movq	-344(%rbp), %rax
	movslq	-328(%rbp), %rcx
	subq	%rax, %rcx
	movl	%ecx, %edx
	movl	%edx, -328(%rbp)
	jmp	LBB3_90
LBB3_79:
	movslq	-332(%rbp), %rax
	cmpq	-344(%rbp), %rax
	jg	LBB3_85
## %bb.80:
	movq	$0, -384(%rbp)
LBB3_81:                                ## =>This Inner Loop Header: Depth=1
	movq	-384(%rbp), %rax
	movslq	-332(%rbp), %rcx
	cmpq	%rcx, %rax
	jae	LBB3_84
## %bb.82:                              ##   in Loop: Header=BB3_81 Depth=1
	movq	-320(%rbp), %rax
	movq	-384(%rbp), %rcx
	movslq	-336(%rbp), %rdx
	subq	%rdx, %rcx
	movb	(%rax,%rcx), %sil
	movq	-320(%rbp), %rax
	movq	-384(%rbp), %rcx
	movb	%sil, (%rax,%rcx)
## %bb.83:                              ##   in Loop: Header=BB3_81 Depth=1
	movq	-384(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -384(%rbp)
	jmp	LBB3_81
LBB3_84:
	movl	-332(%rbp), %eax
	movq	-320(%rbp), %rcx
	movslq	%eax, %rdx
	addq	%rdx, %rcx
	movq	%rcx, -320(%rbp)
	movslq	-332(%rbp), %rcx
	movq	-344(%rbp), %rdx
	subq	%rcx, %rdx
	movq	%rdx, -344(%rbp)
	movl	$0, -332(%rbp)
	jmp	LBB3_91
LBB3_85:
	movq	$0, -392(%rbp)
LBB3_86:                                ## =>This Inner Loop Header: Depth=1
	movq	-392(%rbp), %rax
	cmpq	-344(%rbp), %rax
	jae	LBB3_89
## %bb.87:                              ##   in Loop: Header=BB3_86 Depth=1
	movq	-320(%rbp), %rax
	movq	-392(%rbp), %rcx
	movslq	-336(%rbp), %rdx
	subq	%rdx, %rcx
	movb	(%rax,%rcx), %sil
	movq	-320(%rbp), %rax
	movq	-392(%rbp), %rcx
	movb	%sil, (%rax,%rcx)
## %bb.88:                              ##   in Loop: Header=BB3_86 Depth=1
	movq	-392(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -392(%rbp)
	jmp	LBB3_86
LBB3_89:
	movq	-344(%rbp), %rax
	addq	-320(%rbp), %rax
	movq	%rax, -320(%rbp)
	movq	-344(%rbp), %rax
	movslq	-332(%rbp), %rcx
	subq	%rax, %rcx
	movl	%ecx, %edx
	movl	%edx, -332(%rbp)
LBB3_90:
	movl	-328(%rbp), %eax
	movq	-264(%rbp), %rcx
	movl	%eax, 16(%rcx)
	movl	-332(%rbp), %eax
	movq	-264(%rbp), %rcx
	movl	%eax, 20(%rcx)
	movl	-336(%rbp), %eax
	movq	-264(%rbp), %rcx
	movl	%eax, 24(%rcx)
	movw	-266(%rbp), %dx
	movq	-264(%rbp), %rcx
	movw	%dx, 52(%rcx)
	movw	-268(%rbp), %dx
	movq	-264(%rbp), %rcx
	movw	%dx, 54(%rcx)
	movw	-270(%rbp), %dx
	movq	-264(%rbp), %rcx
	movw	%dx, 56(%rcx)
	movq	-264(%rbp), %rcx
	movq	-288(%rbp), %rsi
	movq	%rsi, 32(%rcx)
	movq	-280(%rbp), %rsi
	movq	%rsi, 40(%rcx)
	movl	-324(%rbp), %eax
	movq	-264(%rbp), %rcx
	movl	%eax, (%rcx)
	movq	-304(%rbp), %rcx
	movq	-256(%rbp), %rsi
	movq	(%rsi), %rsi
	subq	%rsi, %rcx
	movl	%ecx, %eax
	movq	-264(%rbp), %rcx
	movl	%eax, 48(%rcx)
	movq	-312(%rbp), %rcx
	movq	-264(%rbp), %rsi
	movq	%rcx, 8(%rsi)
	movq	-320(%rbp), %rcx
	movq	-256(%rbp), %rsi
	movq	%rcx, 24(%rsi)
	movl	$-2, -244(%rbp)
	jmp	LBB3_94
LBB3_91:
	movq	-344(%rbp), %rax
	subq	$32, %rax
	movq	%rax, -344(%rbp)
LBB3_92:
	jmp	LBB3_13
LBB3_93:
	movq	-320(%rbp), %rax
	movq	-256(%rbp), %rcx
	movq	%rax, 24(%rcx)
	movl	$0, -244(%rbp)
LBB3_94:
	movl	-244(%rbp), %eax
	addq	$480, %rsp              ## imm = 0x1E0
	popq	%rbp
	retq
	.cfi_endproc
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function get_field
_get_field:                             ## @get_field
	.cfi_startproc
## %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	subq	$32, %rsp
	xorl	%eax, %eax
	movb	%al, %cl
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
	movl	%edx, -24(%rbp)
	movl	-20(%rbp), %eax
	addl	-24(%rbp), %eax
	cmpl	$64, %eax
	movb	%cl, -25(%rbp)          ## 1-byte Spill
	jge	LBB4_3
## %bb.1:
	xorl	%eax, %eax
	movb	%al, %cl
	cmpl	$0, -20(%rbp)
	movb	%cl, -25(%rbp)          ## 1-byte Spill
	jl	LBB4_3
## %bb.2:
	cmpl	$32, -24(%rbp)
	setle	%al
	movb	%al, -25(%rbp)          ## 1-byte Spill
LBB4_3:
	movb	-25(%rbp), %al          ## 1-byte Reload
	xorb	$-1, %al
	andb	$1, %al
	movzbl	%al, %ecx
	movslq	%ecx, %rdx
	cmpq	$0, %rdx
	je	LBB4_5
## %bb.4:
	leaq	L___func__.get_field(%rip), %rdi
	leaq	L_.str(%rip), %rsi
	leaq	L_.str.1(%rip), %rcx
	movl	$56, %edx
	callq	___assert_rtn
LBB4_5:
	jmp	LBB4_6
LBB4_6:
	cmpl	$32, -24(%rbp)
	jne	LBB4_8
## %bb.7:
	movq	-16(%rbp), %rax
	movl	-20(%rbp), %ecx
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shrq	%cl, %rax
	movl	%eax, %edx
	movl	%edx, -4(%rbp)
	jmp	LBB4_9
LBB4_8:
	movq	-16(%rbp), %rax
	movl	-20(%rbp), %ecx
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shrq	%cl, %rax
	movl	-24(%rbp), %ecx
                                        ## kill: def $cl killed $ecx
	movl	$1, %edx
	shll	%cl, %edx
	subl	$1, %edx
	movslq	%edx, %rsi
	andq	%rsi, %rax
	movl	%eax, %edx
	movl	%edx, -4(%rbp)
LBB4_9:
	movl	-4(%rbp), %eax
	addq	$32, %rsp
	popq	%rbp
	retq
	.cfi_endproc
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function lzfse_decode_v1_freq_value
_lzfse_decode_v1_freq_value:            ## @lzfse_decode_v1_freq_value
	.cfi_startproc
## %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movl	%edi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movl	-8(%rbp), %edi
	andl	$31, %edi
	movl	%edi, -20(%rbp)
	movl	-20(%rbp), %edi
	movl	%edi, %esi
	leaq	_lzfse_decode_v1_freq_value.lzfse_freq_nbits_table(%rip), %rax
	movsbl	(%rax,%rsi), %edi
	movl	%edi, -24(%rbp)
	movl	-24(%rbp), %edi
	movq	-16(%rbp), %rax
	movl	%edi, (%rax)
	cmpl	$8, -24(%rbp)
	jne	LBB5_2
## %bb.1:
	movl	-8(%rbp), %eax
	shrl	$4, %eax
	andl	$15, %eax
	addl	$8, %eax
	movl	%eax, -4(%rbp)
	jmp	LBB5_5
LBB5_2:
	cmpl	$14, -24(%rbp)
	jne	LBB5_4
## %bb.3:
	movl	-8(%rbp), %eax
	shrl	$4, %eax
	andl	$1023, %eax             ## imm = 0x3FF
	addl	$24, %eax
	movl	%eax, -4(%rbp)
	jmp	LBB5_5
LBB5_4:
	movl	-20(%rbp), %eax
	movl	%eax, %ecx
	leaq	_lzfse_decode_v1_freq_value.lzfse_freq_value_table(%rip), %rdx
	movsbl	(%rdx,%rcx), %eax
	movl	%eax, -4(%rbp)
LBB5_5:
	movl	-4(%rbp), %eax
	popq	%rbp
	retq
	.cfi_endproc
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function fse_mask_lsb64
_fse_mask_lsb64:                        ## @fse_mask_lsb64
	.cfi_startproc
## %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movq	-8(%rbp), %rdi
	movslq	-12(%rbp), %rax
	leaq	_fse_mask_lsb64.mtable(%rip), %rcx
	andq	(%rcx,%rax,8), %rdi
	movq	%rdi, %rax
	popq	%rbp
	retq
	.cfi_endproc
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function copy
_copy:                                  ## @copy
	.cfi_startproc
## %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	subq	$96, %rsp
	movq	%rdi, -56(%rbp)
	movq	%rsi, -64(%rbp)
	movq	%rdx, -72(%rbp)
	movq	-56(%rbp), %rdx
	addq	-72(%rbp), %rdx
	movq	%rdx, -80(%rbp)
LBB7_1:                                 ## =>This Inner Loop Header: Depth=1
	movq	$-1, %rcx
	movq	-56(%rbp), %rax
	movq	-64(%rbp), %rdx
	movq	%rax, -40(%rbp)
	movq	%rdx, -48(%rbp)
	movq	-40(%rbp), %rax
	movq	-48(%rbp), %rdx
	movq	%rdx, -24(%rbp)
	movq	-24(%rbp), %rdx
	movq	(%rdx), %rdx
	movq	%rdx, -32(%rbp)
	movq	-32(%rbp), %rdx
	movq	%rax, -8(%rbp)
	movq	%rdx, -16(%rbp)
	movq	-8(%rbp), %rdi
	leaq	-16(%rbp), %rax
	movq	%rax, %rsi
	movl	$8, %edx
	callq	___memcpy_chk
	movq	-56(%rbp), %rcx
	addq	$8, %rcx
	movq	%rcx, -56(%rbp)
	movq	-64(%rbp), %rcx
	addq	$8, %rcx
	movq	%rcx, -64(%rbp)
	movq	%rax, -88(%rbp)         ## 8-byte Spill
## %bb.2:                               ##   in Loop: Header=BB7_1 Depth=1
	movq	-56(%rbp), %rax
	cmpq	-80(%rbp), %rax
	jb	LBB7_1
## %bb.3:
	addq	$96, %rsp
	popq	%rbp
	retq
	.cfi_endproc
                                        ## -- End function
	.section	__TEXT,__const
	.p2align	4               ## @l_extra_bits
_l_extra_bits:
	.ascii	"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\002\003\005\b"

	.p2align	4               ## @l_base_value
_l_base_value:
	.long	0                       ## 0x0
	.long	1                       ## 0x1
	.long	2                       ## 0x2
	.long	3                       ## 0x3
	.long	4                       ## 0x4
	.long	5                       ## 0x5
	.long	6                       ## 0x6
	.long	7                       ## 0x7
	.long	8                       ## 0x8
	.long	9                       ## 0x9
	.long	10                      ## 0xa
	.long	11                      ## 0xb
	.long	12                      ## 0xc
	.long	13                      ## 0xd
	.long	14                      ## 0xe
	.long	15                      ## 0xf
	.long	16                      ## 0x10
	.long	20                      ## 0x14
	.long	28                      ## 0x1c
	.long	60                      ## 0x3c

	.p2align	4               ## @m_extra_bits
_m_extra_bits:
	.ascii	"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\003\005\b\013"

	.p2align	4               ## @m_base_value
_m_base_value:
	.long	0                       ## 0x0
	.long	1                       ## 0x1
	.long	2                       ## 0x2
	.long	3                       ## 0x3
	.long	4                       ## 0x4
	.long	5                       ## 0x5
	.long	6                       ## 0x6
	.long	7                       ## 0x7
	.long	8                       ## 0x8
	.long	9                       ## 0x9
	.long	10                      ## 0xa
	.long	11                      ## 0xb
	.long	12                      ## 0xc
	.long	13                      ## 0xd
	.long	14                      ## 0xe
	.long	15                      ## 0xf
	.long	16                      ## 0x10
	.long	24                      ## 0x18
	.long	56                      ## 0x38
	.long	312                     ## 0x138

	.p2align	4               ## @d_extra_bits
_d_extra_bits:
	.ascii	"\000\000\000\000\001\001\001\001\002\002\002\002\003\003\003\003\004\004\004\004\005\005\005\005\006\006\006\006\007\007\007\007\b\b\b\b\t\t\t\t\n\n\n\n\013\013\013\013\f\f\f\f\r\r\r\r\016\016\016\016\017\017\017\017"

	.p2align	4               ## @d_base_value
_d_base_value:
	.long	0                       ## 0x0
	.long	1                       ## 0x1
	.long	2                       ## 0x2
	.long	3                       ## 0x3
	.long	4                       ## 0x4
	.long	6                       ## 0x6
	.long	8                       ## 0x8
	.long	10                      ## 0xa
	.long	12                      ## 0xc
	.long	16                      ## 0x10
	.long	20                      ## 0x14
	.long	24                      ## 0x18
	.long	28                      ## 0x1c
	.long	36                      ## 0x24
	.long	44                      ## 0x2c
	.long	52                      ## 0x34
	.long	60                      ## 0x3c
	.long	76                      ## 0x4c
	.long	92                      ## 0x5c
	.long	108                     ## 0x6c
	.long	124                     ## 0x7c
	.long	156                     ## 0x9c
	.long	188                     ## 0xbc
	.long	220                     ## 0xdc
	.long	252                     ## 0xfc
	.long	316                     ## 0x13c
	.long	380                     ## 0x17c
	.long	444                     ## 0x1bc
	.long	508                     ## 0x1fc
	.long	636                     ## 0x27c
	.long	764                     ## 0x2fc
	.long	892                     ## 0x37c
	.long	1020                    ## 0x3fc
	.long	1276                    ## 0x4fc
	.long	1532                    ## 0x5fc
	.long	1788                    ## 0x6fc
	.long	2044                    ## 0x7fc
	.long	2556                    ## 0x9fc
	.long	3068                    ## 0xbfc
	.long	3580                    ## 0xdfc
	.long	4092                    ## 0xffc
	.long	5116                    ## 0x13fc
	.long	6140                    ## 0x17fc
	.long	7164                    ## 0x1bfc
	.long	8188                    ## 0x1ffc
	.long	10236                   ## 0x27fc
	.long	12284                   ## 0x2ffc
	.long	14332                   ## 0x37fc
	.long	16380                   ## 0x3ffc
	.long	20476                   ## 0x4ffc
	.long	24572                   ## 0x5ffc
	.long	28668                   ## 0x6ffc
	.long	32764                   ## 0x7ffc
	.long	40956                   ## 0x9ffc
	.long	49148                   ## 0xbffc
	.long	57340                   ## 0xdffc
	.long	65532                   ## 0xfffc
	.long	81916                   ## 0x13ffc
	.long	98300                   ## 0x17ffc
	.long	114684                  ## 0x1bffc
	.long	131068                  ## 0x1fffc
	.long	163836                  ## 0x27ffc
	.long	196604                  ## 0x2fffc
	.long	229372                  ## 0x37ffc

	.section	__TEXT,__cstring,cstring_literals
L___func__.get_field:                   ## @__func__.get_field
	.asciz	"get_field"

L_.str:                                 ## @.str
	.asciz	"/Users/blacktop/Downloads/lzfse-master/src/lzfse_decode_base.c"

L_.str.1:                               ## @.str.1
	.asciz	"offset + nbits < 64 && offset >= 0 && nbits <= 32"

	.section	__TEXT,__const
	.p2align	4               ## @lzfse_decode_v1_freq_value.lzfse_freq_nbits_table
_lzfse_decode_v1_freq_value.lzfse_freq_nbits_table:
	.ascii	"\002\003\002\005\002\003\002\b\002\003\002\005\002\003\002\016\002\003\002\005\002\003\002\b\002\003\002\005\002\003\002\016"

	.p2align	4               ## @lzfse_decode_v1_freq_value.lzfse_freq_value_table
_lzfse_decode_v1_freq_value.lzfse_freq_value_table:
	.ascii	"\000\002\001\004\000\003\001\377\000\002\001\005\000\003\001\377\000\002\001\006\000\003\001\377\000\002\001\007\000\003\001\377"

	.section	__TEXT,__cstring,cstring_literals
L___func__.fse_in_checked_flush64:      ## @__func__.fse_in_checked_flush64
	.asciz	"fse_in_checked_flush64"

L_.str.2:                               ## @.str.2
	.asciz	"/Users/blacktop/Downloads/lzfse-master/src/lzfse_fse.h"

L_.str.3:                               ## @.str.3
	.asciz	"s->accum_nbits >= 56 && s->accum_nbits < 64"

L_.str.4:                               ## @.str.4
	.asciz	"(s->accum >> s->accum_nbits) == 0"

	.section	__TEXT,__const
	.p2align	4               ## @fse_mask_lsb64.mtable
_fse_mask_lsb64.mtable:
	.quad	0                       ## 0x0
	.quad	1                       ## 0x1
	.quad	3                       ## 0x3
	.quad	7                       ## 0x7
	.quad	15                      ## 0xf
	.quad	31                      ## 0x1f
	.quad	63                      ## 0x3f
	.quad	127                     ## 0x7f
	.quad	255                     ## 0xff
	.quad	511                     ## 0x1ff
	.quad	1023                    ## 0x3ff
	.quad	2047                    ## 0x7ff
	.quad	4095                    ## 0xfff
	.quad	8191                    ## 0x1fff
	.quad	16383                   ## 0x3fff
	.quad	32767                   ## 0x7fff
	.quad	65535                   ## 0xffff
	.quad	131071                  ## 0x1ffff
	.quad	262143                  ## 0x3ffff
	.quad	524287                  ## 0x7ffff
	.quad	1048575                 ## 0xfffff
	.quad	2097151                 ## 0x1fffff
	.quad	4194303                 ## 0x3fffff
	.quad	8388607                 ## 0x7fffff
	.quad	16777215                ## 0xffffff
	.quad	33554431                ## 0x1ffffff
	.quad	67108863                ## 0x3ffffff
	.quad	134217727               ## 0x7ffffff
	.quad	268435455               ## 0xfffffff
	.quad	536870911               ## 0x1fffffff
	.quad	1073741823              ## 0x3fffffff
	.quad	2147483647              ## 0x7fffffff
	.quad	4294967295              ## 0xffffffff
	.quad	8589934591              ## 0x1ffffffff
	.quad	17179869183             ## 0x3ffffffff
	.quad	34359738367             ## 0x7ffffffff
	.quad	68719476735             ## 0xfffffffff
	.quad	137438953471            ## 0x1fffffffff
	.quad	274877906943            ## 0x3fffffffff
	.quad	549755813887            ## 0x7fffffffff
	.quad	1099511627775           ## 0xffffffffff
	.quad	2199023255551           ## 0x1ffffffffff
	.quad	4398046511103           ## 0x3ffffffffff
	.quad	8796093022207           ## 0x7ffffffffff
	.quad	17592186044415          ## 0xfffffffffff
	.quad	35184372088831          ## 0x1fffffffffff
	.quad	70368744177663          ## 0x3fffffffffff
	.quad	140737488355327         ## 0x7fffffffffff
	.quad	281474976710655         ## 0xffffffffffff
	.quad	562949953421311         ## 0x1ffffffffffff
	.quad	1125899906842623        ## 0x3ffffffffffff
	.quad	2251799813685247        ## 0x7ffffffffffff
	.quad	4503599627370495        ## 0xfffffffffffff
	.quad	9007199254740991        ## 0x1fffffffffffff
	.quad	18014398509481983       ## 0x3fffffffffffff
	.quad	36028797018963967       ## 0x7fffffffffffff
	.quad	72057594037927935       ## 0xffffffffffffff
	.quad	144115188075855871      ## 0x1ffffffffffffff
	.quad	288230376151711743      ## 0x3ffffffffffffff
	.quad	576460752303423487      ## 0x7ffffffffffffff
	.quad	1152921504606846975     ## 0xfffffffffffffff
	.quad	2305843009213693951     ## 0x1fffffffffffffff
	.quad	4611686018427387903     ## 0x3fffffffffffffff
	.quad	9223372036854775807     ## 0x7fffffffffffffff
	.quad	-1                      ## 0xffffffffffffffff

	.section	__TEXT,__cstring,cstring_literals
L___func__.fse_in_pull64:               ## @__func__.fse_in_pull64
	.asciz	"fse_in_pull64"

L_.str.5:                               ## @.str.5
	.asciz	"n >= 0 && n <= s->accum_nbits"

L___func__.lzfse_decode_lmd:            ## @__func__.lzfse_decode_lmd
	.asciz	"lzfse_decode_lmd"

L_.str.6:                               ## @.str.6
	.asciz	"l_state < LZFSE_ENCODE_L_STATES"

L_.str.7:                               ## @.str.7
	.asciz	"m_state < LZFSE_ENCODE_M_STATES"

L_.str.8:                               ## @.str.8
	.asciz	"d_state < LZFSE_ENCODE_D_STATES"


.subsections_via_symbols
