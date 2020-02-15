	.section	__TEXT,__text,regular,pure_instructions
	.build_version macos, 10, 15	sdk_version 10, 15
	.intel_syntax noprefix
	.globl	_lzfse_decode           ## -- Begin function lzfse_decode
	.p2align	4, 0x90
_lzfse_decode:                          ## @lzfse_decode
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -16
	sub	rsp, 1952
	mov	rax, qword ptr [rip + ___stack_chk_guard@GOTPCREL]
	mov	rax, qword ptr [rax]
	mov	qword ptr [rsp + 1944], rax
	mov	qword ptr [rsp + 1248], rdi
LBB0_1:                                 ## =>This Loop Header: Depth=1
                                        ##     Child Loop BB0_30 Depth 2
                                        ##     Child Loop BB0_33 Depth 2
                                        ##     Child Loop BB0_36 Depth 2
                                        ##     Child Loop BB0_39 Depth 2
                                        ##     Child Loop BB0_61 Depth 2
	mov	rax, qword ptr [rsp + 1248]
	mov	ecx, dword ptr [rax + 52]
	test	ecx, ecx
	mov	dword ptr [rsp + 180], ecx ## 4-byte Spill
	je	LBB0_2
	jmp	LBB0_148
LBB0_148:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	eax, dword ptr [rsp + 180] ## 4-byte Reload
	sub	eax, 762869346
	mov	dword ptr [rsp + 176], eax ## 4-byte Spill
	je	LBB0_107
	jmp	LBB0_149
LBB0_149:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	eax, dword ptr [rsp + 180] ## 4-byte Reload
	sub	eax, 829978210
	mov	dword ptr [rsp + 172], eax ## 4-byte Spill
	je	LBB0_118
	jmp	LBB0_150
LBB0_150:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	eax, dword ptr [rsp + 180] ## 4-byte Reload
	sub	eax, 846755426
	mov	dword ptr [rsp + 168], eax ## 4-byte Spill
	je	LBB0_118
	jmp	LBB0_151
LBB0_151:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	eax, dword ptr [rsp + 180] ## 4-byte Reload
	sub	eax, 1853388386
	mov	dword ptr [rsp + 164], eax ## 4-byte Spill
	je	LBB0_124
	jmp	LBB0_143
LBB0_2:                                 ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	add	rax, 4
	mov	rcx, qword ptr [rsp + 1248]
	cmp	rax, qword ptr [rcx + 16]
	jbe	LBB0_4
## %bb.3:
	mov	dword ptr [rsp + 1256], -1
	jmp	LBB0_145
LBB0_4:                                 ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	mov	qword ptr [rsp + 1264], rax
	mov	rax, qword ptr [rsp + 1264]
	mov	ecx, dword ptr [rax]
	mov	dword ptr [rsp + 1260], ecx
	mov	ecx, dword ptr [rsp + 1260]
	mov	dword ptr [rsp + 1244], ecx
	cmp	dword ptr [rsp + 1244], 611874402
	jne	LBB0_6
## %bb.5:
	mov	rax, qword ptr [rsp + 1248]
	mov	rcx, qword ptr [rax]
	add	rcx, 4
	mov	qword ptr [rax], rcx
	mov	rax, qword ptr [rsp + 1248]
	mov	dword ptr [rax + 48], 1
	mov	dword ptr [rsp + 1256], 0
	jmp	LBB0_145
LBB0_6:                                 ##   in Loop: Header=BB0_1 Depth=1
	cmp	dword ptr [rsp + 1244], 762869346
	jne	LBB0_10
## %bb.7:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	add	rax, 8
	mov	rcx, qword ptr [rsp + 1248]
	cmp	rax, qword ptr [rcx + 16]
	jbe	LBB0_9
## %bb.8:
	mov	dword ptr [rsp + 1256], -1
	jmp	LBB0_145
LBB0_9:                                 ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	add	rax, 47364
	mov	qword ptr [rsp + 1232], rax
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	add	rax, 4
	mov	qword ptr [rsp + 1280], rax
	mov	rax, qword ptr [rsp + 1280]
	mov	ecx, dword ptr [rax]
	mov	dword ptr [rsp + 1276], ecx
	mov	ecx, dword ptr [rsp + 1276]
	mov	rax, qword ptr [rsp + 1232]
	mov	dword ptr [rax], ecx
	mov	rax, qword ptr [rsp + 1248]
	mov	rdx, qword ptr [rax]
	add	rdx, 8
	mov	qword ptr [rax], rdx
	mov	ecx, dword ptr [rsp + 1244]
	mov	rax, qword ptr [rsp + 1248]
	mov	dword ptr [rax + 52], ecx
	jmp	LBB0_144
LBB0_10:                                ##   in Loop: Header=BB0_1 Depth=1
	cmp	dword ptr [rsp + 1244], 1853388386
	jne	LBB0_14
## %bb.11:                              ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	add	rax, 12
	mov	rcx, qword ptr [rsp + 1248]
	cmp	rax, qword ptr [rcx + 16]
	jbe	LBB0_13
## %bb.12:
	mov	dword ptr [rsp + 1256], -1
	jmp	LBB0_145
LBB0_13:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	add	rax, 47352
	mov	qword ptr [rsp + 1224], rax
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	add	rax, 4
	mov	qword ptr [rsp + 1328], rax
	mov	rax, qword ptr [rsp + 1328]
	mov	ecx, dword ptr [rax]
	mov	dword ptr [rsp + 1324], ecx
	mov	ecx, dword ptr [rsp + 1324]
	mov	rax, qword ptr [rsp + 1224]
	mov	dword ptr [rax], ecx
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	add	rax, 8
	mov	qword ptr [rsp + 1344], rax
	mov	rax, qword ptr [rsp + 1344]
	mov	ecx, dword ptr [rax]
	mov	dword ptr [rsp + 1340], ecx
	mov	ecx, dword ptr [rsp + 1340]
	mov	rax, qword ptr [rsp + 1224]
	mov	dword ptr [rax + 4], ecx
	mov	rax, qword ptr [rsp + 1224]
	mov	dword ptr [rax + 8], 0
	mov	rax, qword ptr [rsp + 1248]
	mov	rdx, qword ptr [rax]
	add	rdx, 12
	mov	qword ptr [rax], rdx
	mov	ecx, dword ptr [rsp + 1244]
	mov	rax, qword ptr [rsp + 1248]
	mov	dword ptr [rax + 52], ecx
	jmp	LBB0_144
LBB0_14:                                ##   in Loop: Header=BB0_1 Depth=1
	cmp	dword ptr [rsp + 1244], 829978210
	je	LBB0_16
## %bb.15:                              ##   in Loop: Header=BB0_1 Depth=1
	cmp	dword ptr [rsp + 1244], 846755426
	jne	LBB0_106
LBB0_16:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	qword ptr [rsp + 440], 0
	cmp	dword ptr [rsp + 1244], 846755426
	jne	LBB0_24
## %bb.17:                              ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	add	rax, 32
	mov	rcx, qword ptr [rsp + 1248]
	cmp	rax, qword ptr [rcx + 16]
	jbe	LBB0_19
## %bb.18:
	mov	dword ptr [rsp + 1256], -1
	jmp	LBB0_145
LBB0_19:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	mov	qword ptr [rsp + 432], rax
	mov	rdi, qword ptr [rsp + 432]
	call	_lzfse_decode_v2_header_size
	mov	eax, eax
	mov	edi, eax
	mov	qword ptr [rsp + 440], rdi
	mov	rdi, qword ptr [rsp + 1248]
	mov	rdi, qword ptr [rdi]
	add	rdi, qword ptr [rsp + 440]
	mov	rcx, qword ptr [rsp + 1248]
	cmp	rdi, qword ptr [rcx + 16]
	jbe	LBB0_21
## %bb.20:
	mov	dword ptr [rsp + 1256], -1
	jmp	LBB0_145
LBB0_21:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rsi, qword ptr [rsp + 432]
	lea	rdi, [rsp + 448]
	call	_lzfse_decode_v1
	mov	dword ptr [rsp + 428], eax
	cmp	dword ptr [rsp + 428], 0
	je	LBB0_23
## %bb.22:
	mov	dword ptr [rsp + 1256], -3
	jmp	LBB0_145
LBB0_23:                                ##   in Loop: Header=BB0_1 Depth=1
	jmp	LBB0_27
LBB0_24:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	add	rax, 772
	mov	rcx, qword ptr [rsp + 1248]
	cmp	rax, qword ptr [rcx + 16]
	jbe	LBB0_26
## %bb.25:
	mov	dword ptr [rsp + 1256], -1
	jmp	LBB0_145
LBB0_26:                                ##   in Loop: Header=BB0_1 Depth=1
	lea	rax, [rsp + 448]
	mov	rcx, qword ptr [rsp + 1248]
	mov	rsi, qword ptr [rcx]
	mov	rdi, rax
	mov	edx, 772
	call	_memcpy
	mov	qword ptr [rsp + 440], 772
LBB0_27:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	add	rax, qword ptr [rsp + 440]
	mov	ecx, dword ptr [rsp + 468]
	mov	edx, ecx
	add	rax, rdx
	mov	ecx, dword ptr [rsp + 472]
	mov	edx, ecx
	add	rax, rdx
	mov	rdx, qword ptr [rsp + 1248]
	cmp	rax, qword ptr [rdx + 16]
	jbe	LBB0_29
## %bb.28:
	mov	dword ptr [rsp + 1256], -1
	jmp	LBB0_145
LBB0_29:                                ##   in Loop: Header=BB0_1 Depth=1
	xor	eax, eax
	lea	rcx, [rsp + 448]
	mov	qword ptr [rsp + 1440], rcx
	mov	dword ptr [rsp + 1436], 0
	mov	edx, dword ptr [rsp + 1436]
	mov	rcx, qword ptr [rsp + 1440]
	mov	esi, dword ptr [rcx]
	cmp	esi, 829978210
	mov	esi, 1
	cmove	esi, eax
	or	edx, esi
	mov	dword ptr [rsp + 1436], edx
	mov	edx, dword ptr [rsp + 1436]
	mov	rcx, qword ptr [rsp + 1440]
	mov	esi, dword ptr [rcx + 12]
	cmp	esi, 40000
	mov	esi, 2
	cmovbe	esi, eax
	or	edx, esi
	mov	dword ptr [rsp + 1436], edx
	mov	edx, dword ptr [rsp + 1436]
	mov	rcx, qword ptr [rsp + 1440]
	mov	esi, dword ptr [rcx + 16]
	cmp	esi, 10000
	mov	esi, 4
	cmovbe	esi, eax
	or	edx, esi
	mov	dword ptr [rsp + 1436], edx
	mov	rcx, qword ptr [rsp + 1440]
	mov	rcx, qword ptr [rcx + 32]
	mov	qword ptr [rsp + 1936], rcx
	mov	edx, dword ptr [rsp + 1436]
	movzx	esi, word ptr [rsp + 1936]
	cmp	esi, 1024
	mov	esi, 8
	cmovl	esi, eax
	or	edx, esi
	mov	dword ptr [rsp + 1436], edx
	mov	edx, dword ptr [rsp + 1436]
	movzx	esi, word ptr [rsp + 1938]
	cmp	esi, 1024
	mov	esi, 16
	cmovl	esi, eax
	or	edx, esi
	mov	dword ptr [rsp + 1436], edx
	mov	edx, dword ptr [rsp + 1436]
	movzx	esi, word ptr [rsp + 1940]
	cmp	esi, 1024
	mov	esi, 32
	cmovl	esi, eax
	or	edx, esi
	mov	dword ptr [rsp + 1436], edx
	mov	edx, dword ptr [rsp + 1436]
	movzx	esi, word ptr [rsp + 1942]
	cmp	esi, 1024
	mov	esi, 64
	cmovl	esi, eax
	or	edx, esi
	mov	dword ptr [rsp + 1436], edx
	mov	edx, dword ptr [rsp + 1436]
	mov	rcx, qword ptr [rsp + 1440]
	movzx	esi, word ptr [rcx + 44]
	cmp	esi, 64
	mov	esi, 128
	cmovl	esi, eax
	or	edx, esi
	mov	dword ptr [rsp + 1436], edx
	mov	edx, dword ptr [rsp + 1436]
	mov	rcx, qword ptr [rsp + 1440]
	movzx	esi, word ptr [rcx + 46]
	cmp	esi, 64
	mov	esi, 256
	cmovl	esi, eax
	or	edx, esi
	mov	dword ptr [rsp + 1436], edx
	mov	edx, dword ptr [rsp + 1436]
	mov	rcx, qword ptr [rsp + 1440]
	movzx	esi, word ptr [rcx + 48]
	cmp	esi, 256
	mov	esi, 512
	cmovl	esi, eax
	or	edx, esi
	mov	dword ptr [rsp + 1436], edx
	mov	rcx, qword ptr [rsp + 1440]
	add	rcx, 50
	mov	qword ptr [rsp + 1480], rcx
	mov	qword ptr [rsp + 1472], 20
	mov	qword ptr [rsp + 1464], 64
	mov	qword ptr [rsp + 1456], 0
	mov	dword ptr [rsp + 1452], 0
LBB0_30:                                ##   Parent Loop BB0_1 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	movsxd	rax, dword ptr [rsp + 1452]
	cmp	rax, qword ptr [rsp + 1472]
	jae	LBB0_32
## %bb.31:                              ##   in Loop: Header=BB0_30 Depth=2
	mov	rax, qword ptr [rsp + 1480]
	movsxd	rcx, dword ptr [rsp + 1452]
	movzx	edx, word ptr [rax + 2*rcx]
	mov	eax, edx
	add	rax, qword ptr [rsp + 1456]
	mov	qword ptr [rsp + 1456], rax
	mov	edx, dword ptr [rsp + 1452]
	add	edx, 1
	mov	dword ptr [rsp + 1452], edx
	jmp	LBB0_30
LBB0_32:                                ##   in Loop: Header=BB0_1 Depth=1
	xor	eax, eax
	mov	rcx, qword ptr [rsp + 1456]
	mov	rdx, qword ptr [rsp + 1464]
	cmp	rcx, rdx
	mov	esi, 4294967295
	mov	edi, eax
	cmova	edi, esi
	mov	dword ptr [rsp + 1432], edi
	mov	esi, dword ptr [rsp + 1436]
	mov	edi, dword ptr [rsp + 1432]
	cmp	edi, 0
	mov	edi, 1024
	cmove	edi, eax
	or	esi, edi
	mov	dword ptr [rsp + 1436], esi
	mov	rcx, qword ptr [rsp + 1440]
	add	rcx, 90
	mov	qword ptr [rsp + 1600], rcx
	mov	qword ptr [rsp + 1592], 20
	mov	qword ptr [rsp + 1584], 64
	mov	qword ptr [rsp + 1576], 0
	mov	dword ptr [rsp + 1572], 0
LBB0_33:                                ##   Parent Loop BB0_1 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	movsxd	rax, dword ptr [rsp + 1572]
	cmp	rax, qword ptr [rsp + 1592]
	jae	LBB0_35
## %bb.34:                              ##   in Loop: Header=BB0_33 Depth=2
	mov	rax, qword ptr [rsp + 1600]
	movsxd	rcx, dword ptr [rsp + 1572]
	movzx	edx, word ptr [rax + 2*rcx]
	mov	eax, edx
	add	rax, qword ptr [rsp + 1576]
	mov	qword ptr [rsp + 1576], rax
	mov	edx, dword ptr [rsp + 1572]
	add	edx, 1
	mov	dword ptr [rsp + 1572], edx
	jmp	LBB0_33
LBB0_35:                                ##   in Loop: Header=BB0_1 Depth=1
	xor	eax, eax
	mov	rcx, qword ptr [rsp + 1576]
	mov	rdx, qword ptr [rsp + 1584]
	cmp	rcx, rdx
	mov	esi, 4294967295
	mov	edi, eax
	cmova	edi, esi
	mov	dword ptr [rsp + 1432], edi
	mov	esi, dword ptr [rsp + 1436]
	mov	edi, dword ptr [rsp + 1432]
	cmp	edi, 0
	mov	edi, 2048
	cmove	edi, eax
	or	esi, edi
	mov	dword ptr [rsp + 1436], esi
	mov	rcx, qword ptr [rsp + 1440]
	add	rcx, 130
	mov	qword ptr [rsp + 1560], rcx
	mov	qword ptr [rsp + 1552], 64
	mov	qword ptr [rsp + 1544], 256
	mov	qword ptr [rsp + 1536], 0
	mov	dword ptr [rsp + 1532], 0
LBB0_36:                                ##   Parent Loop BB0_1 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	movsxd	rax, dword ptr [rsp + 1532]
	cmp	rax, qword ptr [rsp + 1552]
	jae	LBB0_38
## %bb.37:                              ##   in Loop: Header=BB0_36 Depth=2
	mov	rax, qword ptr [rsp + 1560]
	movsxd	rcx, dword ptr [rsp + 1532]
	movzx	edx, word ptr [rax + 2*rcx]
	mov	eax, edx
	add	rax, qword ptr [rsp + 1536]
	mov	qword ptr [rsp + 1536], rax
	mov	edx, dword ptr [rsp + 1532]
	add	edx, 1
	mov	dword ptr [rsp + 1532], edx
	jmp	LBB0_36
LBB0_38:                                ##   in Loop: Header=BB0_1 Depth=1
	xor	eax, eax
	mov	rcx, qword ptr [rsp + 1536]
	mov	rdx, qword ptr [rsp + 1544]
	cmp	rcx, rdx
	mov	esi, 4294967295
	mov	edi, eax
	cmova	edi, esi
	mov	dword ptr [rsp + 1432], edi
	mov	esi, dword ptr [rsp + 1436]
	mov	edi, dword ptr [rsp + 1432]
	cmp	edi, 0
	mov	edi, 4096
	cmove	edi, eax
	or	esi, edi
	mov	dword ptr [rsp + 1436], esi
	mov	rcx, qword ptr [rsp + 1440]
	add	rcx, 258
	mov	qword ptr [rsp + 1520], rcx
	mov	qword ptr [rsp + 1512], 256
	mov	qword ptr [rsp + 1504], 1024
	mov	qword ptr [rsp + 1496], 0
	mov	dword ptr [rsp + 1492], 0
LBB0_39:                                ##   Parent Loop BB0_1 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	movsxd	rax, dword ptr [rsp + 1492]
	cmp	rax, qword ptr [rsp + 1512]
	jae	LBB0_41
## %bb.40:                              ##   in Loop: Header=BB0_39 Depth=2
	mov	rax, qword ptr [rsp + 1520]
	movsxd	rcx, dword ptr [rsp + 1492]
	movzx	edx, word ptr [rax + 2*rcx]
	mov	eax, edx
	add	rax, qword ptr [rsp + 1496]
	mov	qword ptr [rsp + 1496], rax
	mov	edx, dword ptr [rsp + 1492]
	add	edx, 1
	mov	dword ptr [rsp + 1492], edx
	jmp	LBB0_39
LBB0_41:                                ##   in Loop: Header=BB0_1 Depth=1
	xor	eax, eax
	mov	rcx, qword ptr [rsp + 1496]
	mov	rdx, qword ptr [rsp + 1504]
	cmp	rcx, rdx
	mov	esi, 4294967295
	mov	edi, eax
	cmova	edi, esi
	mov	dword ptr [rsp + 1432], edi
	mov	esi, dword ptr [rsp + 1436]
	mov	edi, dword ptr [rsp + 1432]
	cmp	edi, 0
	mov	edi, 8192
	cmove	edi, eax
	or	esi, edi
	mov	dword ptr [rsp + 1436], esi
	cmp	dword ptr [rsp + 1436], 0
	je	LBB0_43
## %bb.42:                              ##   in Loop: Header=BB0_1 Depth=1
	mov	eax, dword ptr [rsp + 1436]
	or	eax, -2147483648
	mov	dword ptr [rsp + 1448], eax
	jmp	LBB0_44
LBB0_43:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	dword ptr [rsp + 1448], 0
LBB0_44:                                ##   in Loop: Header=BB0_1 Depth=1
	cmp	dword ptr [rsp + 1448], 0
	je	LBB0_46
## %bb.45:
	mov	dword ptr [rsp + 1256], -3
	jmp	LBB0_145
LBB0_46:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 440]
	mov	rcx, qword ptr [rsp + 1248]
	add	rax, qword ptr [rcx]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 1248]
	add	rax, 56
	mov	qword ptr [rsp + 416], rax
	mov	edx, dword ptr [rsp + 472]
	mov	rax, qword ptr [rsp + 416]
	mov	dword ptr [rax + 4], edx
	mov	edx, dword ptr [rsp + 464]
	mov	rax, qword ptr [rsp + 416]
	mov	dword ptr [rax], edx
	lea	rax, [rsp + 448]
	add	rax, 258
	mov	rcx, qword ptr [rsp + 416]
	add	rcx, 3136
	mov	edi, 1024
	mov	esi, 256
	mov	rdx, rax
	call	_fse_init_decoder_table
	lea	rcx, [rsp + 448]
	add	rcx, 50
	mov	rdx, qword ptr [rsp + 416]
	add	rdx, 64
	mov	edi, 64
	mov	esi, 20
	mov	qword ptr [rsp + 152], rdx ## 8-byte Spill
	mov	rdx, rcx
	lea	rcx, [rip + _l_extra_bits]
	lea	r8, [rip + _l_base_value]
	mov	r9, qword ptr [rsp + 152] ## 8-byte Reload
	mov	dword ptr [rsp + 148], eax ## 4-byte Spill
	call	_fse_init_value_decoder_table
	lea	rcx, [rsp + 448]
	add	rcx, 90
	mov	rdx, qword ptr [rsp + 416]
	add	rdx, 576
	mov	edi, 64
	mov	esi, 20
	mov	qword ptr [rsp + 136], rdx ## 8-byte Spill
	mov	rdx, rcx
	lea	rcx, [rip + _m_extra_bits]
	lea	r8, [rip + _m_base_value]
	mov	r9, qword ptr [rsp + 136] ## 8-byte Reload
	call	_fse_init_value_decoder_table
	lea	rcx, [rsp + 448]
	add	rcx, 130
	mov	rdx, qword ptr [rsp + 416]
	add	rdx, 1088
	mov	edi, 256
	mov	esi, 64
	mov	qword ptr [rsp + 128], rdx ## 8-byte Spill
	mov	rdx, rcx
	lea	rcx, [rip + _d_extra_bits]
	lea	r8, [rip + _d_base_value]
	mov	r9, qword ptr [rsp + 128] ## 8-byte Reload
	call	_fse_init_value_decoder_table
	mov	rcx, qword ptr [rsp + 1248]
	mov	rcx, qword ptr [rcx + 8]
	mov	qword ptr [rsp + 392], rcx
	mov	eax, dword ptr [rsp + 468]
	mov	rcx, qword ptr [rsp + 1248]
	mov	rdx, qword ptr [rcx]
	mov	eax, eax
	mov	r8d, eax
	add	rdx, r8
	mov	qword ptr [rcx], rdx
	mov	rcx, qword ptr [rsp + 1248]
	mov	rcx, qword ptr [rcx]
	mov	qword ptr [rsp + 384], rcx
	mov	eax, dword ptr [rsp + 476]
	mov	rcx, qword ptr [rsp + 392]
	lea	rdx, [rsp + 400]
	mov	qword ptr [rsp + 1632], rdx
	mov	dword ptr [rsp + 1628], eax
	lea	rdx, [rsp + 384]
	mov	qword ptr [rsp + 1616], rdx
	mov	qword ptr [rsp + 1608], rcx
	cmp	dword ptr [rsp + 1628], 0
	je	LBB0_50
## %bb.47:                              ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1616]
	mov	rax, qword ptr [rax]
	mov	rcx, qword ptr [rsp + 1608]
	add	rcx, 8
	cmp	rax, rcx
	jae	LBB0_49
## %bb.48:                              ##   in Loop: Header=BB0_1 Depth=1
	mov	dword ptr [rsp + 1644], -1
	jmp	LBB0_58
LBB0_49:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rcx, -1
	mov	rax, qword ptr [rsp + 1616]
	mov	rdx, qword ptr [rax]
	add	rdx, -8
	mov	qword ptr [rax], rdx
	mov	rax, qword ptr [rsp + 1632]
	mov	rdx, qword ptr [rsp + 1616]
	mov	rsi, qword ptr [rdx]
	mov	rdi, rax
	mov	edx, 8
	call	___memcpy_chk
	mov	r8d, dword ptr [rsp + 1628]
	add	r8d, 64
	mov	rcx, qword ptr [rsp + 1632]
	mov	dword ptr [rcx + 8], r8d
	mov	qword ptr [rsp + 120], rax ## 8-byte Spill
	jmp	LBB0_53
LBB0_50:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1616]
	mov	rax, qword ptr [rax]
	mov	rcx, qword ptr [rsp + 1608]
	add	rcx, 7
	cmp	rax, rcx
	jae	LBB0_52
## %bb.51:                              ##   in Loop: Header=BB0_1 Depth=1
	mov	dword ptr [rsp + 1644], -1
	jmp	LBB0_58
LBB0_52:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rcx, -1
	mov	rax, qword ptr [rsp + 1616]
	mov	rdx, qword ptr [rax]
	add	rdx, -7
	mov	qword ptr [rax], rdx
	mov	rax, qword ptr [rsp + 1632]
	mov	rdx, qword ptr [rsp + 1616]
	mov	rsi, qword ptr [rdx]
	mov	rdi, rax
	mov	edx, 7
	call	___memcpy_chk
	mov	rcx, qword ptr [rsp + 1632]
	movabs	rdx, 72057594037927935
	and	rdx, qword ptr [rcx]
	mov	qword ptr [rcx], rdx
	mov	r8d, dword ptr [rsp + 1628]
	add	r8d, 56
	mov	rcx, qword ptr [rsp + 1632]
	mov	dword ptr [rcx + 8], r8d
	mov	qword ptr [rsp + 112], rax ## 8-byte Spill
LBB0_53:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1632]
	cmp	dword ptr [rax + 8], 56
	jl	LBB0_56
## %bb.54:                              ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1632]
	cmp	dword ptr [rax + 8], 64
	jge	LBB0_56
## %bb.55:                              ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1632]
	mov	rax, qword ptr [rax]
	mov	rcx, qword ptr [rsp + 1632]
	mov	edx, dword ptr [rcx + 8]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	cmp	rax, 0
	je	LBB0_57
LBB0_56:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	dword ptr [rsp + 1644], -1
	jmp	LBB0_58
LBB0_57:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	dword ptr [rsp + 1644], 0
LBB0_58:                                ##   in Loop: Header=BB0_1 Depth=1
	cmp	dword ptr [rsp + 1644], 0
	je	LBB0_60
## %bb.59:
	mov	dword ptr [rsp + 1256], -3
	jmp	LBB0_145
LBB0_60:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	ax, word ptr [rsp + 480]
	mov	word ptr [rsp + 382], ax
	mov	ax, word ptr [rsp + 482]
	mov	word ptr [rsp + 380], ax
	mov	ax, word ptr [rsp + 484]
	mov	word ptr [rsp + 378], ax
	mov	ax, word ptr [rsp + 486]
	mov	word ptr [rsp + 376], ax
	mov	dword ptr [rsp + 372], 0
LBB0_61:                                ##   Parent Loop BB0_1 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	mov	eax, dword ptr [rsp + 372]
	cmp	eax, dword ptr [rsp + 460]
	jae	LBB0_91
## %bb.62:                              ##   in Loop: Header=BB0_61 Depth=2
	xor	eax, eax
	mov	ecx, eax
	mov	rdx, qword ptr [rsp + 392]
	lea	rsi, [rsp + 400]
	mov	qword ptr [rsp + 1688], rsi
	lea	rsi, [rsp + 384]
	mov	qword ptr [rsp + 1680], rsi
	mov	qword ptr [rsp + 1672], rdx
	mov	rdx, qword ptr [rsp + 1688]
	mov	eax, 63
	sub	eax, dword ptr [rdx + 8]
	and	eax, -8
	mov	dword ptr [rsp + 1668], eax
	mov	rdx, qword ptr [rsp + 1680]
	mov	rdx, qword ptr [rdx]
	mov	eax, dword ptr [rsp + 1668]
	sar	eax, 3
	movsxd	rsi, eax
	sub	rcx, rsi
	add	rdx, rcx
	mov	qword ptr [rsp + 1656], rdx
	mov	rcx, qword ptr [rsp + 1656]
	cmp	rcx, qword ptr [rsp + 1672]
	jae	LBB0_64
## %bb.63:                              ##   in Loop: Header=BB0_61 Depth=2
	mov	dword ptr [rsp + 1696], -1
	jmp	LBB0_71
LBB0_64:                                ##   in Loop: Header=BB0_61 Depth=2
	mov	rax, qword ptr [rsp + 1656]
	mov	rcx, qword ptr [rsp + 1680]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 1656]
	mov	rax, qword ptr [rax]
	mov	qword ptr [rsp + 1648], rax
	mov	rax, qword ptr [rsp + 1688]
	mov	rax, qword ptr [rax]
	mov	edx, dword ptr [rsp + 1668]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	shl	rax, cl
	mov	rdi, qword ptr [rsp + 1648]
	mov	esi, dword ptr [rsp + 1668]
	mov	qword ptr [rsp + 104], rax ## 8-byte Spill
	call	_fse_mask_lsb64
	xor	edx, edx
	mov	cl, dl
	mov	rdi, qword ptr [rsp + 104] ## 8-byte Reload
	or	rdi, rax
	mov	rax, qword ptr [rsp + 1688]
	mov	qword ptr [rax], rdi
	mov	edx, dword ptr [rsp + 1668]
	mov	rax, qword ptr [rsp + 1688]
	add	edx, dword ptr [rax + 8]
	mov	dword ptr [rax + 8], edx
	mov	rax, qword ptr [rsp + 1688]
	cmp	dword ptr [rax + 8], 56
	mov	byte ptr [rsp + 103], cl ## 1-byte Spill
	jl	LBB0_66
## %bb.65:                              ##   in Loop: Header=BB0_61 Depth=2
	mov	rax, qword ptr [rsp + 1688]
	cmp	dword ptr [rax + 8], 64
	setl	cl
	mov	byte ptr [rsp + 103], cl ## 1-byte Spill
LBB0_66:                                ##   in Loop: Header=BB0_61 Depth=2
	mov	al, byte ptr [rsp + 103] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_67
	jmp	LBB0_68
LBB0_67:
	lea	rdi, [rip + L___func__.fse_in_checked_flush64]
	lea	rsi, [rip + L_.str.2]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 376
	call	___assert_rtn
LBB0_68:                                ##   in Loop: Header=BB0_61 Depth=2
	mov	rax, qword ptr [rsp + 1688]
	mov	rax, qword ptr [rax]
	mov	rcx, qword ptr [rsp + 1688]
	mov	edx, dword ptr [rcx + 8]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	cmp	rax, 0
	sete	cl
	xor	cl, -1
	test	cl, 1
	jne	LBB0_69
	jmp	LBB0_70
LBB0_69:
	lea	rdi, [rip + L___func__.fse_in_checked_flush64]
	lea	rsi, [rip + L_.str.2]
	lea	rcx, [rip + L_.str.4]
	mov	edx, 376
	call	___assert_rtn
LBB0_70:                                ##   in Loop: Header=BB0_61 Depth=2
	mov	dword ptr [rsp + 1696], 0
LBB0_71:                                ##   in Loop: Header=BB0_61 Depth=2
	cmp	dword ptr [rsp + 1696], 0
	je	LBB0_73
## %bb.72:
	mov	dword ptr [rsp + 1256], -3
	jmp	LBB0_145
LBB0_73:                                ##   in Loop: Header=BB0_61 Depth=2
	xor	eax, eax
	mov	cl, al
	mov	rdx, qword ptr [rsp + 416]
	add	rdx, 3136
	lea	rsi, [rsp + 382]
	mov	qword ptr [rsp + 1720], rsi
	mov	qword ptr [rsp + 1712], rdx
	lea	rdx, [rsp + 400]
	mov	qword ptr [rsp + 1704], rdx
	mov	rdx, qword ptr [rsp + 1712]
	mov	rsi, qword ptr [rsp + 1720]
	movzx	eax, word ptr [rsi]
	mov	esi, eax
	mov	eax, dword ptr [rdx + 4*rsi]
	mov	dword ptr [rsp + 1700], eax
	mov	eax, dword ptr [rsp + 1700]
	sar	eax, 16
	mov	di, ax
	movzx	eax, di
	mov	rdx, qword ptr [rsp + 1704]
	mov	r8d, dword ptr [rsp + 1700]
	and	r8d, 255
	mov	qword ptr [rsp + 1744], rdx
	mov	dword ptr [rsp + 1740], r8d
	cmp	dword ptr [rsp + 1740], 0
	mov	dword ptr [rsp + 96], eax ## 4-byte Spill
	mov	byte ptr [rsp + 95], cl ## 1-byte Spill
	jl	LBB0_75
## %bb.74:                              ##   in Loop: Header=BB0_61 Depth=2
	mov	eax, dword ptr [rsp + 1740]
	mov	rcx, qword ptr [rsp + 1744]
	cmp	eax, dword ptr [rcx + 8]
	setle	dl
	mov	byte ptr [rsp + 95], dl ## 1-byte Spill
LBB0_75:                                ##   in Loop: Header=BB0_61 Depth=2
	mov	al, byte ptr [rsp + 95] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_76
	jmp	LBB0_77
LBB0_76:
	lea	rdi, [rip + L___func__.fse_in_pull64]
	lea	rsi, [rip + L_.str.2]
	lea	rcx, [rip + L_.str.5]
	mov	edx, 408
	call	___assert_rtn
LBB0_77:                                ##   in Loop: Header=BB0_61 Depth=2
	mov	eax, dword ptr [rsp + 1740]
	mov	rcx, qword ptr [rsp + 1744]
	mov	edx, dword ptr [rcx + 8]
	sub	edx, eax
	mov	dword ptr [rcx + 8], edx
	mov	rcx, qword ptr [rsp + 1744]
	mov	rcx, qword ptr [rcx]
	mov	rsi, qword ptr [rsp + 1744]
	mov	eax, dword ptr [rsi + 8]
	mov	esi, eax
	mov	qword ptr [rsp + 80], rcx ## 8-byte Spill
	mov	rcx, rsi
                                        ## kill: def $cl killed $rcx
	mov	rsi, qword ptr [rsp + 80] ## 8-byte Reload
	shr	rsi, cl
	mov	qword ptr [rsp + 1728], rsi
	mov	rsi, qword ptr [rsp + 1744]
	mov	rdi, qword ptr [rsi]
	mov	rsi, qword ptr [rsp + 1744]
	mov	esi, dword ptr [rsi + 8]
	call	_fse_mask_lsb64
	mov	rdi, qword ptr [rsp + 1744]
	mov	qword ptr [rdi], rax
	mov	rax, qword ptr [rsp + 1728]
	mov	r8w, ax
	movzx	edx, r8w
	mov	esi, dword ptr [rsp + 96] ## 4-byte Reload
	add	esi, edx
	mov	r8w, si
	mov	rax, qword ptr [rsp + 1720]
	mov	word ptr [rax], r8w
	movsxd	rax, dword ptr [rsp + 1700]
	mov	qword ptr [rsp + 1760], rax
	mov	dword ptr [rsp + 1756], 8
	mov	dword ptr [rsp + 1752], 8
	mov	rax, qword ptr [rsp + 1760]
	mov	edx, dword ptr [rsp + 1756]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	esi, dword ptr [rsp + 1752]
	mov	rdi, rax
	call	_fse_mask_lsb64
	xor	edx, edx
	mov	cl, dl
	mov	qword ptr [rsp + 1768], rax
	mov	rax, qword ptr [rsp + 1768]
	mov	r9b, al
	mov	rax, qword ptr [rsp + 416]
	mov	edx, dword ptr [rsp + 372]
	add	edx, 0
	mov	edx, edx
	mov	edi, edx
	mov	byte ptr [rax + rdi + 7232], r9b
	mov	rax, qword ptr [rsp + 416]
	add	rax, 3136
	lea	rdi, [rsp + 380]
	mov	qword ptr [rsp + 1800], rdi
	mov	qword ptr [rsp + 1792], rax
	lea	rax, [rsp + 400]
	mov	qword ptr [rsp + 1784], rax
	mov	rax, qword ptr [rsp + 1792]
	mov	rdi, qword ptr [rsp + 1800]
	movzx	edx, word ptr [rdi]
	mov	edi, edx
	mov	edx, dword ptr [rax + 4*rdi]
	mov	dword ptr [rsp + 1780], edx
	mov	edx, dword ptr [rsp + 1780]
	sar	edx, 16
	mov	r8w, dx
	movzx	edx, r8w
	mov	rax, qword ptr [rsp + 1784]
	mov	esi, dword ptr [rsp + 1780]
	and	esi, 255
	mov	qword ptr [rsp + 1824], rax
	mov	dword ptr [rsp + 1820], esi
	cmp	dword ptr [rsp + 1820], 0
	mov	dword ptr [rsp + 76], edx ## 4-byte Spill
	mov	byte ptr [rsp + 75], cl ## 1-byte Spill
	jl	LBB0_79
## %bb.78:                              ##   in Loop: Header=BB0_61 Depth=2
	mov	eax, dword ptr [rsp + 1820]
	mov	rcx, qword ptr [rsp + 1824]
	cmp	eax, dword ptr [rcx + 8]
	setle	dl
	mov	byte ptr [rsp + 75], dl ## 1-byte Spill
LBB0_79:                                ##   in Loop: Header=BB0_61 Depth=2
	mov	al, byte ptr [rsp + 75] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_80
	jmp	LBB0_81
LBB0_80:
	lea	rdi, [rip + L___func__.fse_in_pull64]
	lea	rsi, [rip + L_.str.2]
	lea	rcx, [rip + L_.str.5]
	mov	edx, 408
	call	___assert_rtn
LBB0_81:                                ##   in Loop: Header=BB0_61 Depth=2
	mov	eax, dword ptr [rsp + 1820]
	mov	rcx, qword ptr [rsp + 1824]
	mov	edx, dword ptr [rcx + 8]
	sub	edx, eax
	mov	dword ptr [rcx + 8], edx
	mov	rcx, qword ptr [rsp + 1824]
	mov	rcx, qword ptr [rcx]
	mov	rsi, qword ptr [rsp + 1824]
	mov	eax, dword ptr [rsi + 8]
	mov	esi, eax
	mov	qword ptr [rsp + 64], rcx ## 8-byte Spill
	mov	rcx, rsi
                                        ## kill: def $cl killed $rcx
	mov	rsi, qword ptr [rsp + 64] ## 8-byte Reload
	shr	rsi, cl
	mov	qword ptr [rsp + 1808], rsi
	mov	rsi, qword ptr [rsp + 1824]
	mov	rdi, qword ptr [rsi]
	mov	rsi, qword ptr [rsp + 1824]
	mov	esi, dword ptr [rsi + 8]
	call	_fse_mask_lsb64
	mov	rdi, qword ptr [rsp + 1824]
	mov	qword ptr [rdi], rax
	mov	rax, qword ptr [rsp + 1808]
	mov	r8w, ax
	movzx	edx, r8w
	mov	esi, dword ptr [rsp + 76] ## 4-byte Reload
	add	esi, edx
	mov	r8w, si
	mov	rax, qword ptr [rsp + 1800]
	mov	word ptr [rax], r8w
	movsxd	rax, dword ptr [rsp + 1780]
	mov	qword ptr [rsp + 1840], rax
	mov	dword ptr [rsp + 1836], 8
	mov	dword ptr [rsp + 1832], 8
	mov	rax, qword ptr [rsp + 1840]
	mov	edx, dword ptr [rsp + 1836]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	esi, dword ptr [rsp + 1832]
	mov	rdi, rax
	call	_fse_mask_lsb64
	xor	edx, edx
	mov	cl, dl
	mov	qword ptr [rsp + 1848], rax
	mov	rax, qword ptr [rsp + 1848]
	mov	r9b, al
	mov	rax, qword ptr [rsp + 416]
	mov	edx, dword ptr [rsp + 372]
	add	edx, 1
	mov	edx, edx
	mov	edi, edx
	mov	byte ptr [rax + rdi + 7232], r9b
	mov	rax, qword ptr [rsp + 416]
	add	rax, 3136
	lea	rdi, [rsp + 378]
	mov	qword ptr [rsp + 1880], rdi
	mov	qword ptr [rsp + 1872], rax
	lea	rax, [rsp + 400]
	mov	qword ptr [rsp + 1864], rax
	mov	rax, qword ptr [rsp + 1872]
	mov	rdi, qword ptr [rsp + 1880]
	movzx	edx, word ptr [rdi]
	mov	edi, edx
	mov	edx, dword ptr [rax + 4*rdi]
	mov	dword ptr [rsp + 1860], edx
	mov	edx, dword ptr [rsp + 1860]
	sar	edx, 16
	mov	r8w, dx
	movzx	edx, r8w
	mov	rax, qword ptr [rsp + 1864]
	mov	esi, dword ptr [rsp + 1860]
	and	esi, 255
	mov	qword ptr [rsp + 1904], rax
	mov	dword ptr [rsp + 1900], esi
	cmp	dword ptr [rsp + 1900], 0
	mov	dword ptr [rsp + 60], edx ## 4-byte Spill
	mov	byte ptr [rsp + 59], cl ## 1-byte Spill
	jl	LBB0_83
## %bb.82:                              ##   in Loop: Header=BB0_61 Depth=2
	mov	eax, dword ptr [rsp + 1900]
	mov	rcx, qword ptr [rsp + 1904]
	cmp	eax, dword ptr [rcx + 8]
	setle	dl
	mov	byte ptr [rsp + 59], dl ## 1-byte Spill
LBB0_83:                                ##   in Loop: Header=BB0_61 Depth=2
	mov	al, byte ptr [rsp + 59] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_84
	jmp	LBB0_85
LBB0_84:
	lea	rdi, [rip + L___func__.fse_in_pull64]
	lea	rsi, [rip + L_.str.2]
	lea	rcx, [rip + L_.str.5]
	mov	edx, 408
	call	___assert_rtn
LBB0_85:                                ##   in Loop: Header=BB0_61 Depth=2
	mov	eax, dword ptr [rsp + 1900]
	mov	rcx, qword ptr [rsp + 1904]
	mov	edx, dword ptr [rcx + 8]
	sub	edx, eax
	mov	dword ptr [rcx + 8], edx
	mov	rcx, qword ptr [rsp + 1904]
	mov	rcx, qword ptr [rcx]
	mov	rsi, qword ptr [rsp + 1904]
	mov	eax, dword ptr [rsi + 8]
	mov	esi, eax
	mov	qword ptr [rsp + 48], rcx ## 8-byte Spill
	mov	rcx, rsi
                                        ## kill: def $cl killed $rcx
	mov	rsi, qword ptr [rsp + 48] ## 8-byte Reload
	shr	rsi, cl
	mov	qword ptr [rsp + 1888], rsi
	mov	rsi, qword ptr [rsp + 1904]
	mov	rdi, qword ptr [rsi]
	mov	rsi, qword ptr [rsp + 1904]
	mov	esi, dword ptr [rsi + 8]
	call	_fse_mask_lsb64
	mov	rdi, qword ptr [rsp + 1904]
	mov	qword ptr [rdi], rax
	mov	rax, qword ptr [rsp + 1888]
	mov	r8w, ax
	movzx	edx, r8w
	mov	esi, dword ptr [rsp + 60] ## 4-byte Reload
	add	esi, edx
	mov	r8w, si
	mov	rax, qword ptr [rsp + 1880]
	mov	word ptr [rax], r8w
	movsxd	rax, dword ptr [rsp + 1860]
	mov	qword ptr [rsp + 1920], rax
	mov	dword ptr [rsp + 1916], 8
	mov	dword ptr [rsp + 1912], 8
	mov	rax, qword ptr [rsp + 1920]
	mov	edx, dword ptr [rsp + 1916]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	esi, dword ptr [rsp + 1912]
	mov	rdi, rax
	call	_fse_mask_lsb64
	xor	edx, edx
	mov	cl, dl
	mov	qword ptr [rsp + 1928], rax
	mov	rax, qword ptr [rsp + 1928]
	mov	r9b, al
	mov	rax, qword ptr [rsp + 416]
	mov	edx, dword ptr [rsp + 372]
	add	edx, 2
	mov	edx, edx
	mov	edi, edx
	mov	byte ptr [rax + rdi + 7232], r9b
	mov	rax, qword ptr [rsp + 416]
	add	rax, 3136
	lea	rdi, [rsp + 376]
	mov	qword ptr [rsp + 1376], rdi
	mov	qword ptr [rsp + 1368], rax
	lea	rax, [rsp + 400]
	mov	qword ptr [rsp + 1360], rax
	mov	rax, qword ptr [rsp + 1368]
	mov	rdi, qword ptr [rsp + 1376]
	movzx	edx, word ptr [rdi]
	mov	edi, edx
	mov	edx, dword ptr [rax + 4*rdi]
	mov	dword ptr [rsp + 1356], edx
	mov	edx, dword ptr [rsp + 1356]
	sar	edx, 16
	mov	r8w, dx
	movzx	edx, r8w
	mov	rax, qword ptr [rsp + 1360]
	mov	esi, dword ptr [rsp + 1356]
	and	esi, 255
	mov	qword ptr [rsp + 1400], rax
	mov	dword ptr [rsp + 1396], esi
	cmp	dword ptr [rsp + 1396], 0
	mov	dword ptr [rsp + 44], edx ## 4-byte Spill
	mov	byte ptr [rsp + 43], cl ## 1-byte Spill
	jl	LBB0_87
## %bb.86:                              ##   in Loop: Header=BB0_61 Depth=2
	mov	eax, dword ptr [rsp + 1396]
	mov	rcx, qword ptr [rsp + 1400]
	cmp	eax, dword ptr [rcx + 8]
	setle	dl
	mov	byte ptr [rsp + 43], dl ## 1-byte Spill
LBB0_87:                                ##   in Loop: Header=BB0_61 Depth=2
	mov	al, byte ptr [rsp + 43] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_88
	jmp	LBB0_89
LBB0_88:
	lea	rdi, [rip + L___func__.fse_in_pull64]
	lea	rsi, [rip + L_.str.2]
	lea	rcx, [rip + L_.str.5]
	mov	edx, 408
	call	___assert_rtn
LBB0_89:                                ##   in Loop: Header=BB0_61 Depth=2
	mov	eax, dword ptr [rsp + 1396]
	mov	rcx, qword ptr [rsp + 1400]
	mov	edx, dword ptr [rcx + 8]
	sub	edx, eax
	mov	dword ptr [rcx + 8], edx
	mov	rcx, qword ptr [rsp + 1400]
	mov	rcx, qword ptr [rcx]
	mov	rsi, qword ptr [rsp + 1400]
	mov	eax, dword ptr [rsi + 8]
	mov	esi, eax
	mov	qword ptr [rsp + 32], rcx ## 8-byte Spill
	mov	rcx, rsi
                                        ## kill: def $cl killed $rcx
	mov	rsi, qword ptr [rsp + 32] ## 8-byte Reload
	shr	rsi, cl
	mov	qword ptr [rsp + 1384], rsi
	mov	rsi, qword ptr [rsp + 1400]
	mov	rdi, qword ptr [rsi]
	mov	rsi, qword ptr [rsp + 1400]
	mov	esi, dword ptr [rsi + 8]
	call	_fse_mask_lsb64
	mov	rdi, qword ptr [rsp + 1400]
	mov	qword ptr [rdi], rax
	mov	rax, qword ptr [rsp + 1384]
	mov	r8w, ax
	movzx	edx, r8w
	mov	esi, dword ptr [rsp + 44] ## 4-byte Reload
	add	esi, edx
	mov	r8w, si
	mov	rax, qword ptr [rsp + 1376]
	mov	word ptr [rax], r8w
	movsxd	rax, dword ptr [rsp + 1356]
	mov	qword ptr [rsp + 1416], rax
	mov	dword ptr [rsp + 1412], 8
	mov	dword ptr [rsp + 1408], 8
	mov	rax, qword ptr [rsp + 1416]
	mov	edx, dword ptr [rsp + 1412]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	esi, dword ptr [rsp + 1408]
	mov	rdi, rax
	call	_fse_mask_lsb64
	mov	qword ptr [rsp + 1424], rax
	mov	rax, qword ptr [rsp + 1424]
	mov	cl, al
	mov	rax, qword ptr [rsp + 416]
	mov	edx, dword ptr [rsp + 372]
	add	edx, 3
	mov	edx, edx
	mov	edi, edx
	mov	byte ptr [rax + rdi + 7232], cl
## %bb.90:                              ##   in Loop: Header=BB0_61 Depth=2
	mov	eax, dword ptr [rsp + 372]
	add	eax, 4
	mov	dword ptr [rsp + 372], eax
	jmp	LBB0_61
LBB0_91:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 416]
	add	rax, 7232
	mov	rcx, qword ptr [rsp + 416]
	mov	qword ptr [rcx + 8], rax
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	mov	edx, dword ptr [rsp + 472]
	mov	ecx, edx
	add	rax, rcx
	mov	qword ptr [rsp + 344], rax
	mov	edx, dword ptr [rsp + 488]
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	lea	rcx, [rsp + 352]
	mov	qword ptr [rsp + 1312], rcx
	mov	dword ptr [rsp + 1308], edx
	lea	rcx, [rsp + 344]
	mov	qword ptr [rsp + 1296], rcx
	mov	qword ptr [rsp + 1288], rax
	cmp	dword ptr [rsp + 1308], 0
	je	LBB0_95
## %bb.92:                              ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1296]
	mov	rax, qword ptr [rax]
	mov	rcx, qword ptr [rsp + 1288]
	add	rcx, 8
	cmp	rax, rcx
	jae	LBB0_94
## %bb.93:                              ##   in Loop: Header=BB0_1 Depth=1
	mov	dword ptr [rsp + 1320], -1
	jmp	LBB0_103
LBB0_94:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rcx, -1
	mov	rax, qword ptr [rsp + 1296]
	mov	rdx, qword ptr [rax]
	add	rdx, -8
	mov	qword ptr [rax], rdx
	mov	rax, qword ptr [rsp + 1312]
	mov	rdx, qword ptr [rsp + 1296]
	mov	rsi, qword ptr [rdx]
	mov	rdi, rax
	mov	edx, 8
	call	___memcpy_chk
	mov	r8d, dword ptr [rsp + 1308]
	add	r8d, 64
	mov	rcx, qword ptr [rsp + 1312]
	mov	dword ptr [rcx + 8], r8d
	mov	qword ptr [rsp + 24], rax ## 8-byte Spill
	jmp	LBB0_98
LBB0_95:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1296]
	mov	rax, qword ptr [rax]
	mov	rcx, qword ptr [rsp + 1288]
	add	rcx, 7
	cmp	rax, rcx
	jae	LBB0_97
## %bb.96:                              ##   in Loop: Header=BB0_1 Depth=1
	mov	dword ptr [rsp + 1320], -1
	jmp	LBB0_103
LBB0_97:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rcx, -1
	mov	rax, qword ptr [rsp + 1296]
	mov	rdx, qword ptr [rax]
	add	rdx, -7
	mov	qword ptr [rax], rdx
	mov	rax, qword ptr [rsp + 1312]
	mov	rdx, qword ptr [rsp + 1296]
	mov	rsi, qword ptr [rdx]
	mov	rdi, rax
	mov	edx, 7
	call	___memcpy_chk
	mov	rcx, qword ptr [rsp + 1312]
	movabs	rdx, 72057594037927935
	and	rdx, qword ptr [rcx]
	mov	qword ptr [rcx], rdx
	mov	r8d, dword ptr [rsp + 1308]
	add	r8d, 56
	mov	rcx, qword ptr [rsp + 1312]
	mov	dword ptr [rcx + 8], r8d
	mov	qword ptr [rsp + 16], rax ## 8-byte Spill
LBB0_98:                                ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1312]
	cmp	dword ptr [rax + 8], 56
	jl	LBB0_101
## %bb.99:                              ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1312]
	cmp	dword ptr [rax + 8], 64
	jge	LBB0_101
## %bb.100:                             ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1312]
	mov	rax, qword ptr [rax]
	mov	rcx, qword ptr [rsp + 1312]
	mov	edx, dword ptr [rcx + 8]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	cmp	rax, 0
	je	LBB0_102
LBB0_101:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	dword ptr [rsp + 1320], -1
	jmp	LBB0_103
LBB0_102:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	dword ptr [rsp + 1320], 0
LBB0_103:                               ##   in Loop: Header=BB0_1 Depth=1
	cmp	dword ptr [rsp + 1320], 0
	je	LBB0_105
## %bb.104:
	mov	dword ptr [rsp + 1256], -3
	jmp	LBB0_145
LBB0_105:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	ax, word ptr [rsp + 492]
	mov	rcx, qword ptr [rsp + 416]
	mov	word ptr [rcx + 52], ax
	mov	ax, word ptr [rsp + 494]
	mov	rcx, qword ptr [rsp + 416]
	mov	word ptr [rcx + 54], ax
	mov	ax, word ptr [rsp + 496]
	mov	rcx, qword ptr [rsp + 416]
	mov	word ptr [rcx + 56], ax
	mov	rcx, qword ptr [rsp + 344]
	mov	rdx, qword ptr [rsp + 1248]
	mov	rdx, qword ptr [rdx]
	sub	rcx, rdx
	mov	esi, ecx
	mov	rcx, qword ptr [rsp + 416]
	mov	dword ptr [rcx + 48], esi
	mov	rcx, qword ptr [rsp + 416]
	mov	dword ptr [rcx + 20], 0
	mov	rcx, qword ptr [rsp + 416]
	mov	dword ptr [rcx + 16], 0
	mov	rcx, qword ptr [rsp + 416]
	mov	dword ptr [rcx + 24], -1
	mov	rcx, qword ptr [rsp + 416]
	mov	rdx, qword ptr [rsp + 352]
	mov	qword ptr [rcx + 32], rdx
	mov	rdx, qword ptr [rsp + 360]
	mov	qword ptr [rcx + 40], rdx
	mov	esi, dword ptr [rsp + 1244]
	mov	rcx, qword ptr [rsp + 1248]
	mov	dword ptr [rcx + 52], esi
	jmp	LBB0_144
LBB0_106:
	mov	dword ptr [rsp + 1256], -3
	jmp	LBB0_145
LBB0_107:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	add	rax, 47364
	mov	qword ptr [rsp + 336], rax
	mov	rax, qword ptr [rsp + 336]
	mov	ecx, dword ptr [rax]
	mov	dword ptr [rsp + 332], ecx
	cmp	dword ptr [rsp + 332], 0
	jne	LBB0_109
## %bb.108:                             ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	dword ptr [rax + 52], 0
	jmp	LBB0_144
LBB0_109:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax + 16]
	mov	rcx, qword ptr [rsp + 1248]
	cmp	rax, qword ptr [rcx]
	ja	LBB0_111
## %bb.110:
	mov	dword ptr [rsp + 1256], -1
	jmp	LBB0_145
LBB0_111:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax + 16]
	mov	rcx, qword ptr [rsp + 1248]
	mov	rcx, qword ptr [rcx]
	sub	rax, rcx
	mov	qword ptr [rsp + 320], rax
	mov	edx, dword ptr [rsp + 332]
	mov	eax, edx
	cmp	rax, qword ptr [rsp + 320]
	jbe	LBB0_113
## %bb.112:                             ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 320]
	mov	ecx, eax
	mov	dword ptr [rsp + 332], ecx
LBB0_113:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax + 40]
	mov	rcx, qword ptr [rsp + 1248]
	cmp	rax, qword ptr [rcx + 24]
	ja	LBB0_115
## %bb.114:
	mov	dword ptr [rsp + 1256], -2
	jmp	LBB0_145
LBB0_115:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax + 40]
	mov	rcx, qword ptr [rsp + 1248]
	mov	rcx, qword ptr [rcx + 24]
	sub	rax, rcx
	mov	qword ptr [rsp + 312], rax
	mov	edx, dword ptr [rsp + 332]
	mov	eax, edx
	cmp	rax, qword ptr [rsp + 312]
	jbe	LBB0_117
## %bb.116:                             ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 312]
	mov	ecx, eax
	mov	dword ptr [rsp + 332], ecx
LBB0_117:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rcx, -1
	mov	rax, qword ptr [rsp + 1248]
	mov	rdi, qword ptr [rax + 24]
	mov	rax, qword ptr [rsp + 1248]
	mov	rsi, qword ptr [rax]
	mov	edx, dword ptr [rsp + 332]
                                        ## kill: def $rdx killed $edx
	call	___memcpy_chk
	mov	r8d, dword ptr [rsp + 332]
	mov	rcx, qword ptr [rsp + 1248]
	mov	rdx, qword ptr [rcx]
	mov	r8d, r8d
	mov	esi, r8d
	add	rdx, rsi
	mov	qword ptr [rcx], rdx
	mov	r8d, dword ptr [rsp + 332]
	mov	rcx, qword ptr [rsp + 1248]
	mov	rdx, qword ptr [rcx + 24]
	mov	r8d, r8d
	mov	esi, r8d
	add	rdx, rsi
	mov	qword ptr [rcx + 24], rdx
	mov	r8d, dword ptr [rsp + 332]
	mov	rcx, qword ptr [rsp + 336]
	mov	r9d, dword ptr [rcx]
	sub	r9d, r8d
	mov	dword ptr [rcx], r9d
	mov	qword ptr [rsp + 8], rax ## 8-byte Spill
	jmp	LBB0_144
LBB0_118:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	add	rax, 56
	mov	qword ptr [rsp + 304], rax
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax + 16]
	mov	rcx, qword ptr [rsp + 1248]
	cmp	rax, qword ptr [rcx]
	jbe	LBB0_120
## %bb.119:                             ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 304]
	mov	ecx, dword ptr [rax + 4]
	mov	eax, ecx
	mov	rdx, qword ptr [rsp + 1248]
	mov	rdx, qword ptr [rdx + 16]
	mov	rsi, qword ptr [rsp + 1248]
	mov	rsi, qword ptr [rsi]
	sub	rdx, rsi
	cmp	rax, rdx
	jbe	LBB0_121
LBB0_120:
	mov	dword ptr [rsp + 1256], -1
	jmp	LBB0_145
LBB0_121:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rdi, qword ptr [rsp + 1248]
	call	_lzfse_decode_lmd
	mov	dword ptr [rsp + 300], eax
	cmp	dword ptr [rsp + 300], 0
	je	LBB0_123
## %bb.122:
	mov	eax, dword ptr [rsp + 300]
	mov	dword ptr [rsp + 1256], eax
	jmp	LBB0_145
LBB0_123:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	dword ptr [rax + 52], 0
	mov	rax, qword ptr [rsp + 304]
	mov	ecx, dword ptr [rax + 4]
	mov	rax, qword ptr [rsp + 1248]
	mov	rdx, qword ptr [rax]
	mov	ecx, ecx
	mov	esi, ecx
	add	rdx, rsi
	mov	qword ptr [rax], rdx
	jmp	LBB0_144
LBB0_124:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	add	rax, 47352
	mov	qword ptr [rsp + 288], rax
	mov	rax, qword ptr [rsp + 288]
	cmp	dword ptr [rax + 4], 0
	jbe	LBB0_127
## %bb.125:                             ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax + 16]
	mov	rcx, qword ptr [rsp + 1248]
	cmp	rax, qword ptr [rcx]
	ja	LBB0_127
## %bb.126:
	mov	dword ptr [rsp + 1256], -1
	jmp	LBB0_145
LBB0_127:                               ##   in Loop: Header=BB0_1 Depth=1
	xor	esi, esi
	lea	rax, [rsp + 200]
	mov	rdi, rax
	mov	edx, 88
	call	_memset
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	mov	qword ptr [rsp + 200], rax
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax + 16]
	mov	qword ptr [rsp + 208], rax
	mov	rax, qword ptr [rsp + 208]
	mov	rdx, qword ptr [rsp + 1248]
	mov	rdx, qword ptr [rdx]
	sub	rax, rdx
	mov	rdx, qword ptr [rsp + 288]
	mov	esi, dword ptr [rdx + 4]
	mov	edx, esi
	cmp	rax, rdx
	jle	LBB0_129
## %bb.128:                             ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax]
	mov	rcx, qword ptr [rsp + 288]
	mov	edx, dword ptr [rcx + 4]
	mov	ecx, edx
	add	rax, rcx
	mov	qword ptr [rsp + 208], rax
LBB0_129:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax + 32]
	mov	qword ptr [rsp + 224], rax
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax + 24]
	mov	qword ptr [rsp + 216], rax
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax + 40]
	mov	qword ptr [rsp + 232], rax
	mov	rax, qword ptr [rsp + 232]
	mov	rcx, qword ptr [rsp + 1248]
	mov	rcx, qword ptr [rcx + 24]
	sub	rax, rcx
	mov	rcx, qword ptr [rsp + 288]
	mov	edx, dword ptr [rcx]
	mov	ecx, edx
	cmp	rax, rcx
	jle	LBB0_131
## %bb.130:                             ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	rax, qword ptr [rax + 24]
	mov	rcx, qword ptr [rsp + 288]
	mov	edx, dword ptr [rcx]
	mov	ecx, edx
	add	rax, rcx
	mov	qword ptr [rsp + 232], rax
LBB0_131:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 288]
	mov	ecx, dword ptr [rax + 8]
	mov	eax, ecx
	mov	qword ptr [rsp + 272], rax
	mov	dword ptr [rsp + 280], 0
	lea	rdi, [rsp + 200]
	call	_lzvn_decode
	mov	rax, qword ptr [rsp + 200]
	mov	rdi, qword ptr [rsp + 1248]
	mov	rdi, qword ptr [rdi]
	sub	rax, rdi
	mov	qword ptr [rsp + 192], rax
	mov	rax, qword ptr [rsp + 216]
	mov	rdi, qword ptr [rsp + 1248]
	mov	rdi, qword ptr [rdi + 24]
	sub	rax, rdi
	mov	qword ptr [rsp + 184], rax
	mov	rax, qword ptr [rsp + 192]
	mov	rdi, qword ptr [rsp + 288]
	mov	ecx, dword ptr [rdi + 4]
	mov	edi, ecx
	cmp	rax, rdi
	ja	LBB0_133
## %bb.132:                             ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 288]
	mov	edx, dword ptr [rcx]
	mov	ecx, edx
	cmp	rax, rcx
	jbe	LBB0_134
LBB0_133:
	mov	dword ptr [rsp + 1256], -3
	jmp	LBB0_145
LBB0_134:                               ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 200]
	mov	rcx, qword ptr [rsp + 1248]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 216]
	mov	rcx, qword ptr [rsp + 1248]
	mov	qword ptr [rcx + 24], rax
	mov	rax, qword ptr [rsp + 192]
	mov	edx, eax
	mov	rax, qword ptr [rsp + 288]
	mov	esi, dword ptr [rax + 4]
	sub	esi, edx
	mov	dword ptr [rax + 4], esi
	mov	rax, qword ptr [rsp + 184]
	mov	edx, eax
	mov	rax, qword ptr [rsp + 288]
	mov	esi, dword ptr [rax]
	sub	esi, edx
	mov	dword ptr [rax], esi
	mov	rax, qword ptr [rsp + 272]
	mov	edx, eax
	mov	rax, qword ptr [rsp + 288]
	mov	dword ptr [rax + 8], edx
	mov	rax, qword ptr [rsp + 288]
	cmp	dword ptr [rax + 4], 0
	jne	LBB0_138
## %bb.135:                             ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 288]
	cmp	dword ptr [rax], 0
	jne	LBB0_138
## %bb.136:                             ##   in Loop: Header=BB0_1 Depth=1
	cmp	dword ptr [rsp + 280], 0
	je	LBB0_138
## %bb.137:                             ##   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rsp + 1248]
	mov	dword ptr [rax + 52], 0
	jmp	LBB0_144
LBB0_138:
	mov	rax, qword ptr [rsp + 288]
	cmp	dword ptr [rax + 4], 0
	je	LBB0_141
## %bb.139:
	mov	rax, qword ptr [rsp + 288]
	cmp	dword ptr [rax], 0
	je	LBB0_141
## %bb.140:
	cmp	dword ptr [rsp + 280], 0
	je	LBB0_142
LBB0_141:
	mov	dword ptr [rsp + 1256], -3
	jmp	LBB0_145
LBB0_142:
	mov	dword ptr [rsp + 1256], -2
	jmp	LBB0_145
LBB0_143:
	mov	dword ptr [rsp + 1256], -3
	jmp	LBB0_145
LBB0_144:                               ##   in Loop: Header=BB0_1 Depth=1
	jmp	LBB0_1
LBB0_145:
	mov	eax, dword ptr [rsp + 1256]
	mov	rcx, qword ptr [rip + ___stack_chk_guard@GOTPCREL]
	mov	rcx, qword ptr [rcx]
	mov	rdx, qword ptr [rsp + 1944]
	cmp	rcx, rdx
	mov	dword ptr [rsp + 4], eax ## 4-byte Spill
	jne	LBB0_147
## %bb.146:
	mov	eax, dword ptr [rsp + 4] ## 4-byte Reload
	mov	rsp, rbp
	pop	rbp
	ret
LBB0_147:
	call	___stack_chk_fail
	ud2
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function lzfse_decode_v2_header_size
_lzfse_decode_v2_header_size:           ## @lzfse_decode_v2_header_size
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -16
	sub	rsp, 16
	xor	esi, esi
	mov	qword ptr [rsp + 8], rdi
	mov	rdi, qword ptr [rsp + 8]
	mov	rdi, qword ptr [rdi + 24]
	mov	edx, 32
	call	_get_field
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function lzfse_decode_v1
_lzfse_decode_v1:                       ## @lzfse_decode_v1
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -16
	sub	rsp, 112
	xor	eax, eax
	mov	rcx, -1
	mov	qword ptr [rsp + 96], rdi
	mov	qword ptr [rsp + 88], rsi
	mov	rsi, qword ptr [rsp + 96]
	mov	rdi, rsi
	mov	esi, eax
	mov	edx, 772
	call	___memset_chk
	xor	esi, esi
	mov	rcx, qword ptr [rsp + 88]
	mov	rcx, qword ptr [rcx + 8]
	mov	qword ptr [rsp + 80], rcx
	mov	rcx, qword ptr [rsp + 88]
	mov	rcx, qword ptr [rcx + 16]
	mov	qword ptr [rsp + 72], rcx
	mov	rcx, qword ptr [rsp + 88]
	mov	rcx, qword ptr [rcx + 24]
	mov	qword ptr [rsp + 64], rcx
	mov	rcx, qword ptr [rsp + 96]
	mov	dword ptr [rcx], 829978210
	mov	rcx, qword ptr [rsp + 88]
	mov	r8d, dword ptr [rcx + 4]
	mov	rcx, qword ptr [rsp + 96]
	mov	dword ptr [rcx + 4], r8d
	mov	rdi, qword ptr [rsp + 80]
	mov	edx, 20
	mov	qword ptr [rsp + 16], rax ## 8-byte Spill
	call	_get_field
	mov	rcx, qword ptr [rsp + 96]
	mov	dword ptr [rcx + 12], eax
	mov	rdi, qword ptr [rsp + 80]
	mov	eax, 20
	mov	esi, eax
	mov	edx, eax
	call	_get_field
	mov	rcx, qword ptr [rsp + 96]
	mov	dword ptr [rcx + 20], eax
	mov	rdi, qword ptr [rsp + 80]
	mov	esi, 60
	mov	edx, 3
	call	_get_field
	xor	esi, esi
	sub	eax, 7
	mov	rcx, qword ptr [rsp + 96]
	mov	dword ptr [rcx + 28], eax
	mov	rdi, qword ptr [rsp + 72]
	mov	edx, 10
	call	_get_field
	mov	r9w, ax
	mov	rcx, qword ptr [rsp + 96]
	mov	word ptr [rcx + 32], r9w
	mov	rdi, qword ptr [rsp + 72]
	mov	eax, 10
	mov	esi, eax
	mov	edx, eax
	call	_get_field
	mov	r9w, ax
	mov	rcx, qword ptr [rsp + 96]
	mov	word ptr [rcx + 34], r9w
	mov	rdi, qword ptr [rsp + 72]
	mov	esi, 20
	mov	edx, 10
	call	_get_field
	mov	r9w, ax
	mov	rcx, qword ptr [rsp + 96]
	mov	word ptr [rcx + 36], r9w
	mov	rdi, qword ptr [rsp + 72]
	mov	esi, 30
	mov	edx, 10
	call	_get_field
	mov	r9w, ax
	mov	rcx, qword ptr [rsp + 96]
	mov	word ptr [rcx + 38], r9w
	mov	rdi, qword ptr [rsp + 80]
	mov	esi, 40
	mov	edx, 20
	call	_get_field
	mov	rcx, qword ptr [rsp + 96]
	mov	dword ptr [rcx + 16], eax
	mov	rdi, qword ptr [rsp + 72]
	mov	esi, 40
	mov	edx, 20
	call	_get_field
	mov	rcx, qword ptr [rsp + 96]
	mov	dword ptr [rcx + 24], eax
	mov	rdi, qword ptr [rsp + 72]
	mov	esi, 60
	mov	edx, 3
	call	_get_field
	sub	eax, 7
	mov	rcx, qword ptr [rsp + 96]
	mov	dword ptr [rcx + 40], eax
	mov	rdi, qword ptr [rsp + 64]
	mov	esi, 32
	mov	edx, 10
	call	_get_field
	mov	r9w, ax
	mov	rcx, qword ptr [rsp + 96]
	mov	word ptr [rcx + 44], r9w
	mov	rdi, qword ptr [rsp + 64]
	mov	esi, 42
	mov	edx, 10
	call	_get_field
	mov	r9w, ax
	mov	rcx, qword ptr [rsp + 96]
	mov	word ptr [rcx + 46], r9w
	mov	rdi, qword ptr [rsp + 64]
	mov	esi, 52
	mov	edx, 10
	call	_get_field
	xor	esi, esi
	mov	r9w, ax
	mov	rcx, qword ptr [rsp + 96]
	mov	word ptr [rcx + 48], r9w
	mov	rcx, qword ptr [rsp + 96]
	mov	eax, dword ptr [rcx + 20]
	mov	rcx, qword ptr [rsp + 96]
	add	eax, dword ptr [rcx + 24]
	mov	rcx, qword ptr [rsp + 96]
	mov	dword ptr [rcx + 8], eax
	mov	rcx, qword ptr [rsp + 96]
	add	rcx, 50
	mov	qword ptr [rsp + 56], rcx
	mov	rcx, qword ptr [rsp + 88]
	add	rcx, 32
	mov	qword ptr [rsp + 48], rcx
	mov	rcx, qword ptr [rsp + 88]
	mov	rdi, qword ptr [rsp + 64]
	mov	edx, 32
	mov	qword ptr [rsp + 8], rcx ## 8-byte Spill
	call	_get_field
	mov	eax, eax
	mov	ecx, eax
	mov	rdi, qword ptr [rsp + 8] ## 8-byte Reload
	add	rdi, rcx
	mov	qword ptr [rsp + 40], rdi
	mov	dword ptr [rsp + 36], 0
	mov	dword ptr [rsp + 32], 0
	mov	rcx, qword ptr [rsp + 40]
	cmp	rcx, qword ptr [rsp + 48]
	jne	LBB2_2
## %bb.1:
	mov	dword ptr [rsp + 108], 0
	jmp	LBB2_17
LBB2_2:
	mov	dword ptr [rsp + 28], 0
LBB2_3:                                 ## =>This Loop Header: Depth=1
                                        ##     Child Loop BB2_5 Depth 2
	cmp	dword ptr [rsp + 28], 360
	jge	LBB2_13
## %bb.4:                               ##   in Loop: Header=BB2_3 Depth=1
	jmp	LBB2_5
LBB2_5:                                 ##   Parent Loop BB2_3 Depth=1
                                        ## =>  This Inner Loop Header: Depth=2
	xor	eax, eax
	mov	cl, al
	mov	rdx, qword ptr [rsp + 48]
	cmp	rdx, qword ptr [rsp + 40]
	mov	byte ptr [rsp + 7], cl  ## 1-byte Spill
	jae	LBB2_7
## %bb.6:                               ##   in Loop: Header=BB2_5 Depth=2
	mov	eax, dword ptr [rsp + 32]
	add	eax, 8
	cmp	eax, 32
	setle	cl
	mov	byte ptr [rsp + 7], cl  ## 1-byte Spill
LBB2_7:                                 ##   in Loop: Header=BB2_5 Depth=2
	mov	al, byte ptr [rsp + 7]  ## 1-byte Reload
	test	al, 1
	jne	LBB2_8
	jmp	LBB2_9
LBB2_8:                                 ##   in Loop: Header=BB2_5 Depth=2
	mov	rax, qword ptr [rsp + 48]
	movzx	ecx, byte ptr [rax]
	mov	edx, dword ptr [rsp + 32]
	mov	dword ptr [rsp], ecx    ## 4-byte Spill
	mov	ecx, edx
                                        ## kill: def $cl killed $ecx
	mov	edx, dword ptr [rsp]    ## 4-byte Reload
	shl	edx, cl
	or	edx, dword ptr [rsp + 36]
	mov	dword ptr [rsp + 36], edx
	mov	edx, dword ptr [rsp + 32]
	add	edx, 8
	mov	dword ptr [rsp + 32], edx
	mov	rax, qword ptr [rsp + 48]
	add	rax, 1
	mov	qword ptr [rsp + 48], rax
	jmp	LBB2_5
LBB2_9:                                 ##   in Loop: Header=BB2_3 Depth=1
	mov	dword ptr [rsp + 24], 0
	mov	edi, dword ptr [rsp + 36]
	lea	rsi, [rsp + 24]
	call	_lzfse_decode_v1_freq_value
	mov	cx, ax
	mov	rsi, qword ptr [rsp + 56]
	movsxd	rdx, dword ptr [rsp + 28]
	mov	word ptr [rsi + 2*rdx], cx
	mov	eax, dword ptr [rsp + 24]
	cmp	eax, dword ptr [rsp + 32]
	jle	LBB2_11
## %bb.10:
	mov	dword ptr [rsp + 108], -1
	jmp	LBB2_17
LBB2_11:                                ##   in Loop: Header=BB2_3 Depth=1
	mov	ecx, dword ptr [rsp + 24]
	mov	eax, dword ptr [rsp + 36]
                                        ## kill: def $cl killed $ecx
	shr	eax, cl
	mov	dword ptr [rsp + 36], eax
	mov	eax, dword ptr [rsp + 24]
	mov	edx, dword ptr [rsp + 32]
	sub	edx, eax
	mov	dword ptr [rsp + 32], edx
## %bb.12:                              ##   in Loop: Header=BB2_3 Depth=1
	mov	eax, dword ptr [rsp + 28]
	add	eax, 1
	mov	dword ptr [rsp + 28], eax
	jmp	LBB2_3
LBB2_13:
	cmp	dword ptr [rsp + 32], 8
	jge	LBB2_15
## %bb.14:
	mov	rax, qword ptr [rsp + 48]
	cmp	rax, qword ptr [rsp + 40]
	je	LBB2_16
LBB2_15:
	mov	dword ptr [rsp + 108], -1
	jmp	LBB2_17
LBB2_16:
	mov	dword ptr [rsp + 108], 0
LBB2_17:
	mov	eax, dword ptr [rsp + 108]
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function lzfse_decode_lmd
_lzfse_decode_lmd:                      ## @lzfse_decode_lmd
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -16
	sub	rsp, 480
	mov	qword ptr [rsp + 224], rdi
	mov	rdi, qword ptr [rsp + 224]
	add	rdi, 56
	mov	qword ptr [rsp + 216], rdi
	mov	rdi, qword ptr [rsp + 216]
	mov	ax, word ptr [rdi + 52]
	mov	word ptr [rsp + 214], ax
	mov	rdi, qword ptr [rsp + 216]
	mov	ax, word ptr [rdi + 54]
	mov	word ptr [rsp + 212], ax
	mov	rdi, qword ptr [rsp + 216]
	mov	ax, word ptr [rdi + 56]
	mov	word ptr [rsp + 210], ax
	mov	rdi, qword ptr [rsp + 216]
	mov	rcx, qword ptr [rdi + 32]
	mov	qword ptr [rsp + 192], rcx
	mov	rcx, qword ptr [rdi + 40]
	mov	qword ptr [rsp + 200], rcx
	mov	rcx, qword ptr [rsp + 224]
	mov	rcx, qword ptr [rcx + 8]
	mov	qword ptr [rsp + 184], rcx
	mov	rcx, qword ptr [rsp + 224]
	mov	rcx, qword ptr [rcx]
	mov	rdi, qword ptr [rsp + 216]
	mov	edx, dword ptr [rdi + 48]
	mov	edi, edx
	add	rcx, rdi
	mov	qword ptr [rsp + 176], rcx
	mov	rcx, qword ptr [rsp + 216]
	mov	rcx, qword ptr [rcx + 8]
	mov	qword ptr [rsp + 168], rcx
	mov	rcx, qword ptr [rsp + 224]
	mov	rcx, qword ptr [rcx + 24]
	mov	qword ptr [rsp + 160], rcx
	mov	rcx, qword ptr [rsp + 216]
	mov	edx, dword ptr [rcx]
	mov	dword ptr [rsp + 156], edx
	mov	rcx, qword ptr [rsp + 216]
	mov	edx, dword ptr [rcx + 16]
	mov	dword ptr [rsp + 152], edx
	mov	rcx, qword ptr [rsp + 216]
	mov	edx, dword ptr [rcx + 20]
	mov	dword ptr [rsp + 148], edx
	mov	rcx, qword ptr [rsp + 216]
	mov	edx, dword ptr [rcx + 24]
	mov	dword ptr [rsp + 144], edx
	movzx	edx, word ptr [rsp + 214]
	cmp	edx, 64
	setl	sil
	xor	sil, -1
	and	sil, 1
	movzx	edx, sil
	movsxd	rcx, edx
	cmp	rcx, 0
	je	LBB3_2
## %bb.1:
	lea	rdi, [rip + L___func__.lzfse_decode_lmd]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.6]
	mov	edx, 171
	call	___assert_rtn
LBB3_2:
	jmp	LBB3_3
LBB3_3:
	movzx	eax, word ptr [rsp + 212]
	cmp	eax, 64
	setl	cl
	xor	cl, -1
	and	cl, 1
	movzx	eax, cl
	movsxd	rdx, eax
	cmp	rdx, 0
	je	LBB3_5
## %bb.4:
	lea	rdi, [rip + L___func__.lzfse_decode_lmd]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.7]
	mov	edx, 172
	call	___assert_rtn
LBB3_5:
	jmp	LBB3_6
LBB3_6:
	movzx	eax, word ptr [rsp + 210]
	cmp	eax, 256
	setl	cl
	xor	cl, -1
	and	cl, 1
	movzx	eax, cl
	movsxd	rdx, eax
	cmp	rdx, 0
	je	LBB3_8
## %bb.7:
	lea	rdi, [rip + L___func__.lzfse_decode_lmd]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.8]
	mov	edx, 173
	call	___assert_rtn
LBB3_8:
	jmp	LBB3_9
LBB3_9:
	mov	rax, qword ptr [rsp + 224]
	mov	rax, qword ptr [rax + 40]
	mov	rcx, qword ptr [rsp + 160]
	sub	rax, rcx
	sub	rax, 32
	mov	qword ptr [rsp + 136], rax
	cmp	dword ptr [rsp + 152], 0
	jne	LBB3_11
## %bb.10:
	cmp	dword ptr [rsp + 148], 0
	je	LBB3_12
LBB3_11:
	jmp	LBB3_56
LBB3_12:
	jmp	LBB3_13
LBB3_13:
	cmp	dword ptr [rsp + 156], 0
	jbe	LBB3_93
## %bb.14:
	xor	eax, eax
	mov	ecx, eax
	mov	rdx, qword ptr [rsp + 184]
	lea	rsi, [rsp + 192]
	mov	qword ptr [rsp + 280], rsi
	lea	rsi, [rsp + 176]
	mov	qword ptr [rsp + 272], rsi
	mov	qword ptr [rsp + 264], rdx
	mov	rdx, qword ptr [rsp + 280]
	mov	eax, 63
	sub	eax, dword ptr [rdx + 8]
	and	eax, -8
	mov	dword ptr [rsp + 260], eax
	mov	rdx, qword ptr [rsp + 272]
	mov	rdx, qword ptr [rdx]
	mov	eax, dword ptr [rsp + 260]
	sar	eax, 3
	movsxd	rsi, eax
	sub	rcx, rsi
	add	rdx, rcx
	mov	qword ptr [rsp + 248], rdx
	mov	rcx, qword ptr [rsp + 248]
	cmp	rcx, qword ptr [rsp + 264]
	jae	LBB3_16
## %bb.15:
	mov	dword ptr [rsp + 288], -1
	jmp	LBB3_23
LBB3_16:
	mov	rax, qword ptr [rsp + 248]
	mov	rcx, qword ptr [rsp + 272]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 248]
	mov	rax, qword ptr [rax]
	mov	qword ptr [rsp + 240], rax
	mov	rax, qword ptr [rsp + 280]
	mov	rax, qword ptr [rax]
	mov	edx, dword ptr [rsp + 260]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	shl	rax, cl
	mov	rdi, qword ptr [rsp + 240]
	mov	esi, dword ptr [rsp + 260]
	mov	qword ptr [rsp + 80], rax ## 8-byte Spill
	call	_fse_mask_lsb64
	xor	edx, edx
	mov	cl, dl
	mov	rdi, qword ptr [rsp + 80] ## 8-byte Reload
	or	rdi, rax
	mov	rax, qword ptr [rsp + 280]
	mov	qword ptr [rax], rdi
	mov	edx, dword ptr [rsp + 260]
	mov	rax, qword ptr [rsp + 280]
	add	edx, dword ptr [rax + 8]
	mov	dword ptr [rax + 8], edx
	mov	rax, qword ptr [rsp + 280]
	cmp	dword ptr [rax + 8], 56
	mov	byte ptr [rsp + 79], cl ## 1-byte Spill
	jl	LBB3_18
## %bb.17:
	mov	rax, qword ptr [rsp + 280]
	cmp	dword ptr [rax + 8], 64
	setl	cl
	mov	byte ptr [rsp + 79], cl ## 1-byte Spill
LBB3_18:
	mov	al, byte ptr [rsp + 79] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB3_19
	jmp	LBB3_20
LBB3_19:
	lea	rdi, [rip + L___func__.fse_in_checked_flush64]
	lea	rsi, [rip + L_.str.2]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 376
	call	___assert_rtn
LBB3_20:
	mov	rax, qword ptr [rsp + 280]
	mov	rax, qword ptr [rax]
	mov	rcx, qword ptr [rsp + 280]
	mov	edx, dword ptr [rcx + 8]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	cmp	rax, 0
	sete	cl
	xor	cl, -1
	test	cl, 1
	jne	LBB3_21
	jmp	LBB3_22
LBB3_21:
	lea	rdi, [rip + L___func__.fse_in_checked_flush64]
	lea	rsi, [rip + L_.str.2]
	lea	rcx, [rip + L_.str.4]
	mov	edx, 376
	call	___assert_rtn
LBB3_22:
	mov	dword ptr [rsp + 288], 0
LBB3_23:
	mov	eax, dword ptr [rsp + 288]
	mov	dword ptr [rsp + 132], eax
	cmp	dword ptr [rsp + 132], 0
	je	LBB3_25
## %bb.24:
	mov	dword ptr [rsp + 236], -3
	jmp	LBB3_94
LBB3_25:
	xor	eax, eax
	mov	cl, al
	mov	rdx, qword ptr [rsp + 216]
	add	rdx, 64
	lea	rsi, [rsp + 214]
	mov	qword ptr [rsp + 320], rsi
	mov	qword ptr [rsp + 312], rdx
	lea	rdx, [rsp + 192]
	mov	qword ptr [rsp + 304], rdx
	mov	rdx, qword ptr [rsp + 312]
	mov	rsi, qword ptr [rsp + 320]
	movzx	eax, word ptr [rsi]
	mov	esi, eax
	mov	rdx, qword ptr [rdx + 8*rsi]
	mov	qword ptr [rsp + 296], rdx
	mov	rdx, qword ptr [rsp + 304]
	movzx	eax, byte ptr [rsp + 296]
	mov	qword ptr [rsp + 344], rdx
	mov	dword ptr [rsp + 340], eax
	cmp	dword ptr [rsp + 340], 0
	mov	byte ptr [rsp + 78], cl ## 1-byte Spill
	jl	LBB3_27
## %bb.26:
	mov	eax, dword ptr [rsp + 340]
	mov	rcx, qword ptr [rsp + 344]
	cmp	eax, dword ptr [rcx + 8]
	setle	dl
	mov	byte ptr [rsp + 78], dl ## 1-byte Spill
LBB3_27:
	mov	al, byte ptr [rsp + 78] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB3_28
	jmp	LBB3_29
LBB3_28:
	lea	rdi, [rip + L___func__.fse_in_pull64]
	lea	rsi, [rip + L_.str.2]
	lea	rcx, [rip + L_.str.5]
	mov	edx, 408
	call	___assert_rtn
LBB3_29:
	mov	eax, dword ptr [rsp + 340]
	mov	rcx, qword ptr [rsp + 344]
	mov	edx, dword ptr [rcx + 8]
	sub	edx, eax
	mov	dword ptr [rcx + 8], edx
	mov	rcx, qword ptr [rsp + 344]
	mov	rcx, qword ptr [rcx]
	mov	rsi, qword ptr [rsp + 344]
	mov	eax, dword ptr [rsi + 8]
	mov	esi, eax
	mov	qword ptr [rsp + 64], rcx ## 8-byte Spill
	mov	rcx, rsi
                                        ## kill: def $cl killed $rcx
	mov	rsi, qword ptr [rsp + 64] ## 8-byte Reload
	shr	rsi, cl
	mov	qword ptr [rsp + 328], rsi
	mov	rsi, qword ptr [rsp + 344]
	mov	rdi, qword ptr [rsi]
	mov	rsi, qword ptr [rsp + 344]
	mov	esi, dword ptr [rsi + 8]
	call	_fse_mask_lsb64
	mov	rdi, qword ptr [rsp + 344]
	mov	qword ptr [rdi], rax
	mov	rax, qword ptr [rsp + 328]
	mov	edx, eax
	mov	dword ptr [rsp + 292], edx
	movsx	edx, word ptr [rsp + 298]
	mov	esi, dword ptr [rsp + 292]
	movzx	ecx, byte ptr [rsp + 297]
                                        ## kill: def $cl killed $ecx
	shr	esi, cl
	add	edx, esi
	mov	r8w, dx
	mov	rax, qword ptr [rsp + 320]
	mov	word ptr [rax], r8w
	movsxd	rax, dword ptr [rsp + 300]
	mov	edx, dword ptr [rsp + 292]
	mov	edi, edx
	movzx	esi, byte ptr [rsp + 297]
	mov	qword ptr [rsp + 56], rax ## 8-byte Spill
	call	_fse_mask_lsb64
	mov	rdi, qword ptr [rsp + 56] ## 8-byte Reload
	add	rdi, rax
	mov	edx, edi
	mov	dword ptr [rsp + 152], edx
	movzx	edx, word ptr [rsp + 214]
	cmp	edx, 64
	setl	cl
	xor	cl, -1
	and	cl, 1
	movzx	edx, cl
	movsxd	rax, edx
	cmp	rax, 0
	je	LBB3_31
## %bb.30:
	lea	rdi, [rip + L___func__.lzfse_decode_lmd]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.6]
	mov	edx, 198
	call	___assert_rtn
LBB3_31:
	jmp	LBB3_32
LBB3_32:
	mov	rax, qword ptr [rsp + 168]
	movsxd	rcx, dword ptr [rsp + 152]
	add	rax, rcx
	mov	rcx, qword ptr [rsp + 216]
	add	rcx, 7232
	add	rcx, 40000
	add	rcx, 64
	cmp	rax, rcx
	jb	LBB3_34
## %bb.33:
	mov	dword ptr [rsp + 236], -3
	jmp	LBB3_94
LBB3_34:
	mov	dword ptr [rsp + 132], 0
	cmp	dword ptr [rsp + 132], 0
	je	LBB3_36
## %bb.35:
	mov	dword ptr [rsp + 236], -3
	jmp	LBB3_94
LBB3_36:
	xor	eax, eax
	mov	cl, al
	mov	rdx, qword ptr [rsp + 216]
	add	rdx, 576
	lea	rsi, [rsp + 212]
	mov	qword ptr [rsp + 384], rsi
	mov	qword ptr [rsp + 376], rdx
	lea	rdx, [rsp + 192]
	mov	qword ptr [rsp + 368], rdx
	mov	rdx, qword ptr [rsp + 376]
	mov	rsi, qword ptr [rsp + 384]
	movzx	eax, word ptr [rsi]
	mov	esi, eax
	mov	rdx, qword ptr [rdx + 8*rsi]
	mov	qword ptr [rsp + 360], rdx
	mov	rdx, qword ptr [rsp + 368]
	movzx	eax, byte ptr [rsp + 360]
	mov	qword ptr [rsp + 408], rdx
	mov	dword ptr [rsp + 404], eax
	cmp	dword ptr [rsp + 404], 0
	mov	byte ptr [rsp + 55], cl ## 1-byte Spill
	jl	LBB3_38
## %bb.37:
	mov	eax, dword ptr [rsp + 404]
	mov	rcx, qword ptr [rsp + 408]
	cmp	eax, dword ptr [rcx + 8]
	setle	dl
	mov	byte ptr [rsp + 55], dl ## 1-byte Spill
LBB3_38:
	mov	al, byte ptr [rsp + 55] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB3_39
	jmp	LBB3_40
LBB3_39:
	lea	rdi, [rip + L___func__.fse_in_pull64]
	lea	rsi, [rip + L_.str.2]
	lea	rcx, [rip + L_.str.5]
	mov	edx, 408
	call	___assert_rtn
LBB3_40:
	mov	eax, dword ptr [rsp + 404]
	mov	rcx, qword ptr [rsp + 408]
	mov	edx, dword ptr [rcx + 8]
	sub	edx, eax
	mov	dword ptr [rcx + 8], edx
	mov	rcx, qword ptr [rsp + 408]
	mov	rcx, qword ptr [rcx]
	mov	rsi, qword ptr [rsp + 408]
	mov	eax, dword ptr [rsi + 8]
	mov	esi, eax
	mov	qword ptr [rsp + 40], rcx ## 8-byte Spill
	mov	rcx, rsi
                                        ## kill: def $cl killed $rcx
	mov	rsi, qword ptr [rsp + 40] ## 8-byte Reload
	shr	rsi, cl
	mov	qword ptr [rsp + 392], rsi
	mov	rsi, qword ptr [rsp + 408]
	mov	rdi, qword ptr [rsi]
	mov	rsi, qword ptr [rsp + 408]
	mov	esi, dword ptr [rsi + 8]
	call	_fse_mask_lsb64
	mov	rdi, qword ptr [rsp + 408]
	mov	qword ptr [rdi], rax
	mov	rax, qword ptr [rsp + 392]
	mov	edx, eax
	mov	dword ptr [rsp + 356], edx
	movsx	edx, word ptr [rsp + 362]
	mov	esi, dword ptr [rsp + 356]
	movzx	ecx, byte ptr [rsp + 361]
                                        ## kill: def $cl killed $ecx
	shr	esi, cl
	add	edx, esi
	mov	r8w, dx
	mov	rax, qword ptr [rsp + 384]
	mov	word ptr [rax], r8w
	movsxd	rax, dword ptr [rsp + 364]
	mov	edx, dword ptr [rsp + 356]
	mov	edi, edx
	movzx	esi, byte ptr [rsp + 361]
	mov	qword ptr [rsp + 32], rax ## 8-byte Spill
	call	_fse_mask_lsb64
	mov	rdi, qword ptr [rsp + 32] ## 8-byte Reload
	add	rdi, rax
	mov	edx, edi
	mov	dword ptr [rsp + 148], edx
	movzx	edx, word ptr [rsp + 212]
	cmp	edx, 64
	setl	cl
	xor	cl, -1
	and	cl, 1
	movzx	edx, cl
	movsxd	rax, edx
	cmp	rax, 0
	je	LBB3_42
## %bb.41:
	lea	rdi, [rip + L___func__.lzfse_decode_lmd]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.7]
	mov	edx, 207
	call	___assert_rtn
LBB3_42:
	jmp	LBB3_43
LBB3_43:
	mov	dword ptr [rsp + 132], 0
	cmp	dword ptr [rsp + 132], 0
	je	LBB3_45
## %bb.44:
	mov	dword ptr [rsp + 236], -3
	jmp	LBB3_94
LBB3_45:
	xor	eax, eax
	mov	cl, al
	mov	rdx, qword ptr [rsp + 216]
	add	rdx, 1088
	lea	rsi, [rsp + 210]
	mov	qword ptr [rsp + 448], rsi
	mov	qword ptr [rsp + 440], rdx
	lea	rdx, [rsp + 192]
	mov	qword ptr [rsp + 432], rdx
	mov	rdx, qword ptr [rsp + 440]
	mov	rsi, qword ptr [rsp + 448]
	movzx	eax, word ptr [rsi]
	mov	esi, eax
	mov	rdx, qword ptr [rdx + 8*rsi]
	mov	qword ptr [rsp + 424], rdx
	mov	rdx, qword ptr [rsp + 432]
	movzx	eax, byte ptr [rsp + 424]
	mov	qword ptr [rsp + 472], rdx
	mov	dword ptr [rsp + 468], eax
	cmp	dword ptr [rsp + 468], 0
	mov	byte ptr [rsp + 31], cl ## 1-byte Spill
	jl	LBB3_47
## %bb.46:
	mov	eax, dword ptr [rsp + 468]
	mov	rcx, qword ptr [rsp + 472]
	cmp	eax, dword ptr [rcx + 8]
	setle	dl
	mov	byte ptr [rsp + 31], dl ## 1-byte Spill
LBB3_47:
	mov	al, byte ptr [rsp + 31] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB3_48
	jmp	LBB3_49
LBB3_48:
	lea	rdi, [rip + L___func__.fse_in_pull64]
	lea	rsi, [rip + L_.str.2]
	lea	rcx, [rip + L_.str.5]
	mov	edx, 408
	call	___assert_rtn
LBB3_49:
	mov	eax, dword ptr [rsp + 468]
	mov	rcx, qword ptr [rsp + 472]
	mov	edx, dword ptr [rcx + 8]
	sub	edx, eax
	mov	dword ptr [rcx + 8], edx
	mov	rcx, qword ptr [rsp + 472]
	mov	rcx, qword ptr [rcx]
	mov	rsi, qword ptr [rsp + 472]
	mov	eax, dword ptr [rsi + 8]
	mov	esi, eax
	mov	qword ptr [rsp + 16], rcx ## 8-byte Spill
	mov	rcx, rsi
                                        ## kill: def $cl killed $rcx
	mov	rsi, qword ptr [rsp + 16] ## 8-byte Reload
	shr	rsi, cl
	mov	qword ptr [rsp + 456], rsi
	mov	rsi, qword ptr [rsp + 472]
	mov	rdi, qword ptr [rsi]
	mov	rsi, qword ptr [rsp + 472]
	mov	esi, dword ptr [rsi + 8]
	call	_fse_mask_lsb64
	mov	rdi, qword ptr [rsp + 472]
	mov	qword ptr [rdi], rax
	mov	rax, qword ptr [rsp + 456]
	mov	edx, eax
	mov	dword ptr [rsp + 420], edx
	movsx	edx, word ptr [rsp + 426]
	mov	esi, dword ptr [rsp + 420]
	movzx	ecx, byte ptr [rsp + 425]
                                        ## kill: def $cl killed $ecx
	shr	esi, cl
	add	edx, esi
	mov	r8w, dx
	mov	rax, qword ptr [rsp + 448]
	mov	word ptr [rax], r8w
	movsxd	rax, dword ptr [rsp + 428]
	mov	edx, dword ptr [rsp + 420]
	mov	edi, edx
	movzx	esi, byte ptr [rsp + 425]
	mov	qword ptr [rsp + 8], rax ## 8-byte Spill
	call	_fse_mask_lsb64
	mov	rdi, qword ptr [rsp + 8] ## 8-byte Reload
	add	rdi, rax
	mov	edx, edi
	mov	dword ptr [rsp + 128], edx
	movzx	edx, word ptr [rsp + 210]
	cmp	edx, 256
	setl	cl
	xor	cl, -1
	and	cl, 1
	movzx	edx, cl
	movsxd	rax, edx
	cmp	rax, 0
	je	LBB3_51
## %bb.50:
	lea	rdi, [rip + L___func__.lzfse_decode_lmd]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.8]
	mov	edx, 213
	call	___assert_rtn
LBB3_51:
	jmp	LBB3_52
LBB3_52:
	cmp	dword ptr [rsp + 128], 0
	je	LBB3_54
## %bb.53:
	mov	eax, dword ptr [rsp + 128]
	mov	dword ptr [rsp + 4], eax ## 4-byte Spill
	jmp	LBB3_55
LBB3_54:
	mov	eax, dword ptr [rsp + 144]
	mov	dword ptr [rsp + 4], eax ## 4-byte Spill
LBB3_55:
	mov	eax, dword ptr [rsp + 4] ## 4-byte Reload
	mov	dword ptr [rsp + 144], eax
	mov	eax, dword ptr [rsp + 156]
	add	eax, -1
	mov	dword ptr [rsp + 156], eax
LBB3_56:
	mov	eax, dword ptr [rsp + 144]
	mov	ecx, eax
	mov	rdx, qword ptr [rsp + 160]
	movsxd	rsi, dword ptr [rsp + 152]
	add	rdx, rsi
	mov	rsi, qword ptr [rsp + 224]
	mov	rsi, qword ptr [rsi + 32]
	sub	rdx, rsi
	cmp	rcx, rdx
	jle	LBB3_58
## %bb.57:
	mov	dword ptr [rsp + 236], -3
	jmp	LBB3_94
LBB3_58:
	mov	eax, dword ptr [rsp + 152]
	add	eax, dword ptr [rsp + 148]
	movsxd	rcx, eax
	cmp	rcx, qword ptr [rsp + 136]
	jg	LBB3_68
## %bb.59:
	mov	eax, dword ptr [rsp + 152]
	add	eax, dword ptr [rsp + 148]
	movsxd	rcx, eax
	mov	rdx, qword ptr [rsp + 136]
	sub	rdx, rcx
	mov	qword ptr [rsp + 136], rdx
	mov	rdi, qword ptr [rsp + 160]
	mov	rsi, qword ptr [rsp + 168]
	movsxd	rdx, dword ptr [rsp + 152]
	call	_copy
	mov	eax, dword ptr [rsp + 152]
	mov	rcx, qword ptr [rsp + 160]
	movsxd	rdx, eax
	add	rcx, rdx
	mov	qword ptr [rsp + 160], rcx
	mov	eax, dword ptr [rsp + 152]
	mov	rcx, qword ptr [rsp + 168]
	movsxd	rdx, eax
	add	rcx, rdx
	mov	qword ptr [rsp + 168], rcx
	cmp	dword ptr [rsp + 144], 8
	jge	LBB3_61
## %bb.60:
	mov	eax, dword ptr [rsp + 144]
	cmp	eax, dword ptr [rsp + 148]
	jl	LBB3_62
LBB3_61:
	xor	eax, eax
	mov	ecx, eax
	mov	rdi, qword ptr [rsp + 160]
	mov	rdx, qword ptr [rsp + 160]
	movsxd	rsi, dword ptr [rsp + 144]
	sub	rcx, rsi
	add	rdx, rcx
	movsxd	rcx, dword ptr [rsp + 148]
	mov	rsi, rdx
	mov	rdx, rcx
	call	_copy
	jmp	LBB3_67
LBB3_62:
	mov	qword ptr [rsp + 120], 0
LBB3_63:                                ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 120]
	movsxd	rcx, dword ptr [rsp + 148]
	cmp	rax, rcx
	jae	LBB3_66
## %bb.64:                              ##   in Loop: Header=BB3_63 Depth=1
	mov	rax, qword ptr [rsp + 160]
	mov	rcx, qword ptr [rsp + 120]
	movsxd	rdx, dword ptr [rsp + 144]
	sub	rcx, rdx
	mov	sil, byte ptr [rax + rcx]
	mov	rax, qword ptr [rsp + 160]
	mov	rcx, qword ptr [rsp + 120]
	mov	byte ptr [rax + rcx], sil
## %bb.65:                              ##   in Loop: Header=BB3_63 Depth=1
	mov	rax, qword ptr [rsp + 120]
	add	rax, 1
	mov	qword ptr [rsp + 120], rax
	jmp	LBB3_63
LBB3_66:
	jmp	LBB3_67
LBB3_67:
	mov	eax, dword ptr [rsp + 148]
	mov	rcx, qword ptr [rsp + 160]
	movsxd	rdx, eax
	add	rcx, rdx
	mov	qword ptr [rsp + 160], rcx
	jmp	LBB3_92
LBB3_68:
	mov	rax, qword ptr [rsp + 136]
	add	rax, 32
	mov	qword ptr [rsp + 136], rax
	movsxd	rax, dword ptr [rsp + 152]
	cmp	rax, qword ptr [rsp + 136]
	jg	LBB3_74
## %bb.69:
	mov	qword ptr [rsp + 112], 0
LBB3_70:                                ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 112]
	movsxd	rcx, dword ptr [rsp + 152]
	cmp	rax, rcx
	jae	LBB3_73
## %bb.71:                              ##   in Loop: Header=BB3_70 Depth=1
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 112]
	mov	dl, byte ptr [rax + rcx]
	mov	rax, qword ptr [rsp + 160]
	mov	rcx, qword ptr [rsp + 112]
	mov	byte ptr [rax + rcx], dl
## %bb.72:                              ##   in Loop: Header=BB3_70 Depth=1
	mov	rax, qword ptr [rsp + 112]
	add	rax, 1
	mov	qword ptr [rsp + 112], rax
	jmp	LBB3_70
LBB3_73:
	mov	eax, dword ptr [rsp + 152]
	mov	rcx, qword ptr [rsp + 160]
	movsxd	rdx, eax
	add	rcx, rdx
	mov	qword ptr [rsp + 160], rcx
	mov	eax, dword ptr [rsp + 152]
	mov	rcx, qword ptr [rsp + 168]
	movsxd	rdx, eax
	add	rcx, rdx
	mov	qword ptr [rsp + 168], rcx
	movsxd	rcx, dword ptr [rsp + 152]
	mov	rdx, qword ptr [rsp + 136]
	sub	rdx, rcx
	mov	qword ptr [rsp + 136], rdx
	mov	dword ptr [rsp + 152], 0
	jmp	LBB3_79
LBB3_74:
	mov	qword ptr [rsp + 104], 0
LBB3_75:                                ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 104]
	cmp	rax, qword ptr [rsp + 136]
	jae	LBB3_78
## %bb.76:                              ##   in Loop: Header=BB3_75 Depth=1
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 104]
	mov	dl, byte ptr [rax + rcx]
	mov	rax, qword ptr [rsp + 160]
	mov	rcx, qword ptr [rsp + 104]
	mov	byte ptr [rax + rcx], dl
## %bb.77:                              ##   in Loop: Header=BB3_75 Depth=1
	mov	rax, qword ptr [rsp + 104]
	add	rax, 1
	mov	qword ptr [rsp + 104], rax
	jmp	LBB3_75
LBB3_78:
	mov	rax, qword ptr [rsp + 136]
	add	rax, qword ptr [rsp + 160]
	mov	qword ptr [rsp + 160], rax
	mov	rax, qword ptr [rsp + 136]
	add	rax, qword ptr [rsp + 168]
	mov	qword ptr [rsp + 168], rax
	mov	rax, qword ptr [rsp + 136]
	movsxd	rcx, dword ptr [rsp + 152]
	sub	rcx, rax
	mov	edx, ecx
	mov	dword ptr [rsp + 152], edx
	jmp	LBB3_90
LBB3_79:
	movsxd	rax, dword ptr [rsp + 148]
	cmp	rax, qword ptr [rsp + 136]
	jg	LBB3_85
## %bb.80:
	mov	qword ptr [rsp + 96], 0
LBB3_81:                                ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 96]
	movsxd	rcx, dword ptr [rsp + 148]
	cmp	rax, rcx
	jae	LBB3_84
## %bb.82:                              ##   in Loop: Header=BB3_81 Depth=1
	mov	rax, qword ptr [rsp + 160]
	mov	rcx, qword ptr [rsp + 96]
	movsxd	rdx, dword ptr [rsp + 144]
	sub	rcx, rdx
	mov	sil, byte ptr [rax + rcx]
	mov	rax, qword ptr [rsp + 160]
	mov	rcx, qword ptr [rsp + 96]
	mov	byte ptr [rax + rcx], sil
## %bb.83:                              ##   in Loop: Header=BB3_81 Depth=1
	mov	rax, qword ptr [rsp + 96]
	add	rax, 1
	mov	qword ptr [rsp + 96], rax
	jmp	LBB3_81
LBB3_84:
	mov	eax, dword ptr [rsp + 148]
	mov	rcx, qword ptr [rsp + 160]
	movsxd	rdx, eax
	add	rcx, rdx
	mov	qword ptr [rsp + 160], rcx
	movsxd	rcx, dword ptr [rsp + 148]
	mov	rdx, qword ptr [rsp + 136]
	sub	rdx, rcx
	mov	qword ptr [rsp + 136], rdx
	mov	dword ptr [rsp + 148], 0
	jmp	LBB3_91
LBB3_85:
	mov	qword ptr [rsp + 88], 0
LBB3_86:                                ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 88]
	cmp	rax, qword ptr [rsp + 136]
	jae	LBB3_89
## %bb.87:                              ##   in Loop: Header=BB3_86 Depth=1
	mov	rax, qword ptr [rsp + 160]
	mov	rcx, qword ptr [rsp + 88]
	movsxd	rdx, dword ptr [rsp + 144]
	sub	rcx, rdx
	mov	sil, byte ptr [rax + rcx]
	mov	rax, qword ptr [rsp + 160]
	mov	rcx, qword ptr [rsp + 88]
	mov	byte ptr [rax + rcx], sil
## %bb.88:                              ##   in Loop: Header=BB3_86 Depth=1
	mov	rax, qword ptr [rsp + 88]
	add	rax, 1
	mov	qword ptr [rsp + 88], rax
	jmp	LBB3_86
LBB3_89:
	mov	rax, qword ptr [rsp + 136]
	add	rax, qword ptr [rsp + 160]
	mov	qword ptr [rsp + 160], rax
	mov	rax, qword ptr [rsp + 136]
	movsxd	rcx, dword ptr [rsp + 148]
	sub	rcx, rax
	mov	edx, ecx
	mov	dword ptr [rsp + 148], edx
LBB3_90:
	mov	eax, dword ptr [rsp + 152]
	mov	rcx, qword ptr [rsp + 216]
	mov	dword ptr [rcx + 16], eax
	mov	eax, dword ptr [rsp + 148]
	mov	rcx, qword ptr [rsp + 216]
	mov	dword ptr [rcx + 20], eax
	mov	eax, dword ptr [rsp + 144]
	mov	rcx, qword ptr [rsp + 216]
	mov	dword ptr [rcx + 24], eax
	mov	dx, word ptr [rsp + 214]
	mov	rcx, qword ptr [rsp + 216]
	mov	word ptr [rcx + 52], dx
	mov	dx, word ptr [rsp + 212]
	mov	rcx, qword ptr [rsp + 216]
	mov	word ptr [rcx + 54], dx
	mov	dx, word ptr [rsp + 210]
	mov	rcx, qword ptr [rsp + 216]
	mov	word ptr [rcx + 56], dx
	mov	rcx, qword ptr [rsp + 216]
	mov	rsi, qword ptr [rsp + 192]
	mov	qword ptr [rcx + 32], rsi
	mov	rsi, qword ptr [rsp + 200]
	mov	qword ptr [rcx + 40], rsi
	mov	eax, dword ptr [rsp + 156]
	mov	rcx, qword ptr [rsp + 216]
	mov	dword ptr [rcx], eax
	mov	rcx, qword ptr [rsp + 176]
	mov	rsi, qword ptr [rsp + 224]
	mov	rsi, qword ptr [rsi]
	sub	rcx, rsi
	mov	eax, ecx
	mov	rcx, qword ptr [rsp + 216]
	mov	dword ptr [rcx + 48], eax
	mov	rcx, qword ptr [rsp + 168]
	mov	rsi, qword ptr [rsp + 216]
	mov	qword ptr [rsi + 8], rcx
	mov	rcx, qword ptr [rsp + 160]
	mov	rsi, qword ptr [rsp + 224]
	mov	qword ptr [rsi + 24], rcx
	mov	dword ptr [rsp + 236], -2
	jmp	LBB3_94
LBB3_91:
	mov	rax, qword ptr [rsp + 136]
	sub	rax, 32
	mov	qword ptr [rsp + 136], rax
LBB3_92:
	jmp	LBB3_13
LBB3_93:
	mov	rax, qword ptr [rsp + 160]
	mov	rcx, qword ptr [rsp + 224]
	mov	qword ptr [rcx + 24], rax
	mov	dword ptr [rsp + 236], 0
LBB3_94:
	mov	eax, dword ptr [rsp + 236]
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function get_field
_get_field:                             ## @get_field
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -16
	sub	rsp, 32
	xor	eax, eax
	mov	cl, al
	mov	qword ptr [rsp + 16], rdi
	mov	dword ptr [rsp + 12], esi
	mov	dword ptr [rsp + 8], edx
	mov	eax, dword ptr [rsp + 12]
	add	eax, dword ptr [rsp + 8]
	cmp	eax, 64
	mov	byte ptr [rsp + 7], cl  ## 1-byte Spill
	jge	LBB4_3
## %bb.1:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 12], 0
	mov	byte ptr [rsp + 7], cl  ## 1-byte Spill
	jl	LBB4_3
## %bb.2:
	cmp	dword ptr [rsp + 8], 32
	setle	al
	mov	byte ptr [rsp + 7], al  ## 1-byte Spill
LBB4_3:
	mov	al, byte ptr [rsp + 7]  ## 1-byte Reload
	xor	al, -1
	and	al, 1
	movzx	ecx, al
	movsxd	rdx, ecx
	cmp	rdx, 0
	je	LBB4_5
## %bb.4:
	lea	rdi, [rip + L___func__.get_field]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 56
	call	___assert_rtn
LBB4_5:
	jmp	LBB4_6
LBB4_6:
	cmp	dword ptr [rsp + 8], 32
	jne	LBB4_8
## %bb.7:
	mov	rax, qword ptr [rsp + 16]
	mov	ecx, dword ptr [rsp + 12]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, eax
	mov	dword ptr [rsp + 28], edx
	jmp	LBB4_9
LBB4_8:
	mov	rax, qword ptr [rsp + 16]
	mov	ecx, dword ptr [rsp + 12]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	ecx, dword ptr [rsp + 8]
                                        ## kill: def $cl killed $ecx
	mov	edx, 1
	shl	edx, cl
	sub	edx, 1
	movsxd	rsi, edx
	and	rax, rsi
	mov	edx, eax
	mov	dword ptr [rsp + 28], edx
LBB4_9:
	mov	eax, dword ptr [rsp + 28]
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function lzfse_decode_v1_freq_value
_lzfse_decode_v1_freq_value:            ## @lzfse_decode_v1_freq_value
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -8
	sub	rsp, 32
	mov	dword ptr [rsp + 24], edi
	mov	qword ptr [rsp + 16], rsi
	mov	edi, dword ptr [rsp + 24]
	and	edi, 31
	mov	dword ptr [rsp + 12], edi
	mov	edi, dword ptr [rsp + 12]
	mov	esi, edi
	lea	rax, [rip + _lzfse_decode_v1_freq_value.lzfse_freq_nbits_table]
	movsx	edi, byte ptr [rax + rsi]
	mov	dword ptr [rsp + 8], edi
	mov	edi, dword ptr [rsp + 8]
	mov	rax, qword ptr [rsp + 16]
	mov	dword ptr [rax], edi
	cmp	dword ptr [rsp + 8], 8
	jne	LBB5_2
## %bb.1:
	mov	eax, dword ptr [rsp + 24]
	shr	eax, 4
	and	eax, 15
	add	eax, 8
	mov	dword ptr [rsp + 28], eax
	jmp	LBB5_5
LBB5_2:
	cmp	dword ptr [rsp + 8], 14
	jne	LBB5_4
## %bb.3:
	mov	eax, dword ptr [rsp + 24]
	shr	eax, 4
	and	eax, 1023
	add	eax, 24
	mov	dword ptr [rsp + 28], eax
	jmp	LBB5_5
LBB5_4:
	mov	eax, dword ptr [rsp + 12]
	mov	ecx, eax
	lea	rdx, [rip + _lzfse_decode_v1_freq_value.lzfse_freq_value_table]
	movsx	eax, byte ptr [rdx + rcx]
	mov	dword ptr [rsp + 28], eax
LBB5_5:
	mov	eax, dword ptr [rsp + 28]
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function fse_mask_lsb64
_fse_mask_lsb64:                        ## @fse_mask_lsb64
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -8
	sub	rsp, 16
	mov	qword ptr [rsp + 8], rdi
	mov	dword ptr [rsp + 4], esi
	mov	rdi, qword ptr [rsp + 8]
	movsxd	rax, dword ptr [rsp + 4]
	lea	rcx, [rip + _fse_mask_lsb64.mtable]
	and	rdi, qword ptr [rcx + 8*rax]
	mov	rax, rdi
	mov	rsp, rbp
	pop	rbp
	ret
                                        ## -- End function
	.p2align	4, 0x90         ## -- Begin function copy
_copy:                                  ## @copy
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -16
	sub	rsp, 96
	mov	qword ptr [rsp + 40], rdi
	mov	qword ptr [rsp + 32], rsi
	mov	qword ptr [rsp + 24], rdx
	mov	rdx, qword ptr [rsp + 40]
	add	rdx, qword ptr [rsp + 24]
	mov	qword ptr [rsp + 16], rdx
LBB7_1:                                 ## =>This Inner Loop Header: Depth=1
	mov	rcx, -1
	mov	rax, qword ptr [rsp + 40]
	mov	rdx, qword ptr [rsp + 32]
	mov	qword ptr [rsp + 56], rax
	mov	qword ptr [rsp + 48], rdx
	mov	rax, qword ptr [rsp + 56]
	mov	rdx, qword ptr [rsp + 48]
	mov	qword ptr [rsp + 72], rdx
	mov	rdx, qword ptr [rsp + 72]
	mov	rdx, qword ptr [rdx]
	mov	qword ptr [rsp + 64], rdx
	mov	rdx, qword ptr [rsp + 64]
	mov	qword ptr [rsp + 88], rax
	mov	qword ptr [rsp + 80], rdx
	mov	rdi, qword ptr [rsp + 88]
	lea	rax, [rsp + 80]
	mov	rsi, rax
	mov	edx, 8
	call	___memcpy_chk
	mov	rcx, qword ptr [rsp + 40]
	add	rcx, 8
	mov	qword ptr [rsp + 40], rcx
	mov	rcx, qword ptr [rsp + 32]
	add	rcx, 8
	mov	qword ptr [rsp + 32], rcx
	mov	qword ptr [rsp + 8], rax ## 8-byte Spill
## %bb.2:                               ##   in Loop: Header=BB7_1 Depth=1
	mov	rax, qword ptr [rsp + 40]
	cmp	rax, qword ptr [rsp + 16]
	jb	LBB7_1
## %bb.3:
	mov	rsp, rbp
	pop	rbp
	ret
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
