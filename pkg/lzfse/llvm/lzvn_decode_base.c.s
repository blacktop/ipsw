	.section	__TEXT,__text,regular,pure_instructions
	.build_version macos, 10, 15	sdk_version 10, 15
	.intel_syntax noprefix
	.globl	_lzvn_decode            ## -- Begin function lzvn_decode
	.p2align	4, 0x90
_lzvn_decode:                           ## @lzvn_decode
## %bb.0:
	push	rbp
	mov	rbp, rsp
	and	rsp, -16
	sub	rsp, 656
	mov	qword ptr [rsp + 208], rdi
	mov	rdi, qword ptr [rsp + 208]
	mov	rdi, qword ptr [rdi + 8]
	mov	rax, qword ptr [rsp + 208]
	mov	rax, qword ptr [rax]
	sub	rdi, rax
	mov	qword ptr [rsp + 200], rdi
	mov	rax, qword ptr [rsp + 208]
	mov	rax, qword ptr [rax + 32]
	mov	rdi, qword ptr [rsp + 208]
	mov	rdi, qword ptr [rdi + 16]
	sub	rax, rdi
	mov	qword ptr [rsp + 192], rax
	cmp	qword ptr [rsp + 200], 0
	je	LBB0_2
## %bb.1:
	cmp	qword ptr [rsp + 192], 0
	jne	LBB0_3
LBB0_2:
	jmp	LBB0_247
LBB0_3:
	mov	rax, qword ptr [rsp + 208]
	mov	rax, qword ptr [rax]
	mov	qword ptr [rsp + 184], rax
	mov	rax, qword ptr [rsp + 208]
	mov	rax, qword ptr [rax + 16]
	mov	qword ptr [rsp + 176], rax
	mov	rax, qword ptr [rsp + 208]
	mov	rax, qword ptr [rax + 72]
	mov	qword ptr [rsp + 168], rax
	mov	rax, qword ptr [rsp + 208]
	cmp	qword ptr [rax + 48], 0
	jne	LBB0_5
## %bb.4:
	mov	rax, qword ptr [rsp + 208]
	cmp	qword ptr [rax + 56], 0
	je	LBB0_10
LBB0_5:
	mov	rax, qword ptr [rsp + 208]
	mov	rax, qword ptr [rax + 48]
	mov	qword ptr [rsp + 152], rax
	mov	rax, qword ptr [rsp + 208]
	mov	rax, qword ptr [rax + 56]
	mov	qword ptr [rsp + 160], rax
	mov	rax, qword ptr [rsp + 208]
	mov	rax, qword ptr [rax + 64]
	mov	qword ptr [rsp + 168], rax
	mov	qword ptr [rsp + 144], 0
	mov	rax, qword ptr [rsp + 208]
	mov	qword ptr [rax + 64], 0
	mov	rax, qword ptr [rsp + 208]
	mov	qword ptr [rax + 56], 0
	mov	rax, qword ptr [rsp + 208]
	mov	qword ptr [rax + 48], 0
	cmp	qword ptr [rsp + 160], 0
	jne	LBB0_7
## %bb.6:
	jmp	LBB0_217
LBB0_7:
	cmp	qword ptr [rsp + 152], 0
	jne	LBB0_9
## %bb.8:
	jmp	LBB0_164
LBB0_9:
	jmp	LBB0_144
LBB0_10:
	mov	rax, qword ptr [rsp + 184]
	mov	cl, byte ptr [rax]
	mov	byte ptr [rsp + 143], cl
	movzx	edx, byte ptr [rsp + 143]
	mov	eax, edx
	lea	rsi, [rip + _lzvn_decode.opc_tbl]
	mov	rax, qword ptr [rsi + 8*rax]
	mov	qword ptr [rsp + 64], rax ## 8-byte Spill
	jmp	LBB0_248
Ltmp0:                                  ## Block address taken
LBB0_11:
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 16], rax
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 72], rax
	mov	qword ptr [rsp + 144], 2
	movzx	edx, byte ptr [rsp + 143]
	mov	eax, edx
	mov	qword ptr [rsp + 224], rax
	mov	dword ptr [rsp + 220], 6
	mov	dword ptr [rsp + 216], 2
	mov	edx, dword ptr [rsp + 220]
	mov	eax, edx
	cmp	rax, 64
	setb	sil
	xor	sil, -1
	test	sil, 1
	jne	LBB0_12
	jmp	LBB0_13
LBB0_12:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 478
	call	___assert_rtn
LBB0_13:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 216], 0
	mov	byte ptr [rsp + 63], cl ## 1-byte Spill
	jbe	LBB0_15
## %bb.14:
	mov	eax, dword ptr [rsp + 216]
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	mov	byte ptr [rsp + 63], dl ## 1-byte Spill
LBB0_15:
	mov	al, byte ptr [rsp + 63] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_16
	jmp	LBB0_17
LBB0_16:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 479
	call	___assert_rtn
LBB0_17:
	mov	eax, dword ptr [rsp + 220]
	add	eax, dword ptr [rsp + 216]
	mov	eax, eax
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_18
	jmp	LBB0_19
LBB0_18:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 480
	call	___assert_rtn
LBB0_19:
	mov	eax, dword ptr [rsp + 216]
	mov	ecx, eax
	cmp	rcx, 64
	jne	LBB0_21
## %bb.20:
	mov	rax, qword ptr [rsp + 224]
	mov	qword ptr [rsp + 232], rax
	jmp	LBB0_22
LBB0_21:
	mov	rax, qword ptr [rsp + 224]
	mov	ecx, dword ptr [rsp + 220]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, dword ptr [rsp + 216]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	mov	esi, 1
	shl	rsi, cl
	sub	rsi, 1
	and	rax, rsi
	mov	qword ptr [rsp + 232], rax
LBB0_22:
	mov	rax, qword ptr [rsp + 232]
	mov	qword ptr [rsp + 152], rax
	movzx	ecx, byte ptr [rsp + 143]
	mov	eax, ecx
	mov	qword ptr [rsp + 248], rax
	mov	dword ptr [rsp + 244], 3
	mov	dword ptr [rsp + 240], 3
	mov	ecx, dword ptr [rsp + 244]
	mov	eax, ecx
	cmp	rax, 64
	setb	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_23
	jmp	LBB0_24
LBB0_23:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 478
	call	___assert_rtn
LBB0_24:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 240], 0
	mov	byte ptr [rsp + 62], cl ## 1-byte Spill
	jbe	LBB0_26
## %bb.25:
	mov	eax, dword ptr [rsp + 240]
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	mov	byte ptr [rsp + 62], dl ## 1-byte Spill
LBB0_26:
	mov	al, byte ptr [rsp + 62] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_27
	jmp	LBB0_28
LBB0_27:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 479
	call	___assert_rtn
LBB0_28:
	mov	eax, dword ptr [rsp + 244]
	add	eax, dword ptr [rsp + 240]
	mov	eax, eax
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_29
	jmp	LBB0_30
LBB0_29:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 480
	call	___assert_rtn
LBB0_30:
	mov	eax, dword ptr [rsp + 240]
	mov	ecx, eax
	cmp	rcx, 64
	jne	LBB0_32
## %bb.31:
	mov	rax, qword ptr [rsp + 248]
	mov	qword ptr [rsp + 256], rax
	jmp	LBB0_33
LBB0_32:
	mov	rax, qword ptr [rsp + 248]
	mov	ecx, dword ptr [rsp + 244]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, dword ptr [rsp + 240]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	mov	esi, 1
	shl	rsi, cl
	sub	rsi, 1
	and	rax, rsi
	mov	qword ptr [rsp + 256], rax
LBB0_33:
	mov	rax, qword ptr [rsp + 256]
	add	rax, 3
	mov	qword ptr [rsp + 160], rax
	mov	rax, qword ptr [rsp + 200]
	mov	rcx, qword ptr [rsp + 144]
	add	rcx, qword ptr [rsp + 152]
	cmp	rax, rcx
	ja	LBB0_35
## %bb.34:
	jmp	LBB0_247
LBB0_35:
	movzx	eax, byte ptr [rsp + 143]
	mov	ecx, eax
	mov	qword ptr [rsp + 272], rcx
	mov	dword ptr [rsp + 268], 0
	mov	dword ptr [rsp + 264], 3
	mov	eax, dword ptr [rsp + 268]
	mov	ecx, eax
	cmp	rcx, 64
	setb	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_36
	jmp	LBB0_37
LBB0_36:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 478
	call	___assert_rtn
LBB0_37:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 264], 0
	mov	byte ptr [rsp + 61], cl ## 1-byte Spill
	jbe	LBB0_39
## %bb.38:
	mov	eax, dword ptr [rsp + 264]
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	mov	byte ptr [rsp + 61], dl ## 1-byte Spill
LBB0_39:
	mov	al, byte ptr [rsp + 61] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_40
	jmp	LBB0_41
LBB0_40:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 479
	call	___assert_rtn
LBB0_41:
	mov	eax, dword ptr [rsp + 268]
	add	eax, dword ptr [rsp + 264]
	mov	eax, eax
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_42
	jmp	LBB0_43
LBB0_42:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 480
	call	___assert_rtn
LBB0_43:
	mov	eax, dword ptr [rsp + 264]
	mov	ecx, eax
	cmp	rcx, 64
	jne	LBB0_45
## %bb.44:
	mov	rax, qword ptr [rsp + 272]
	mov	qword ptr [rsp + 280], rax
	jmp	LBB0_46
LBB0_45:
	mov	rax, qword ptr [rsp + 272]
	mov	ecx, dword ptr [rsp + 268]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, dword ptr [rsp + 264]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	mov	esi, 1
	shl	rsi, cl
	sub	rsi, 1
	and	rax, rsi
	mov	qword ptr [rsp + 280], rax
LBB0_46:
	mov	rax, qword ptr [rsp + 280]
	shl	rax, 8
	mov	rcx, qword ptr [rsp + 184]
	movzx	edx, byte ptr [rcx + 1]
	mov	ecx, edx
	or	rax, rcx
	mov	qword ptr [rsp + 168], rax
	jmp	LBB0_144
Ltmp1:                                  ## Block address taken
LBB0_47:
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 16], rax
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 72], rax
	mov	qword ptr [rsp + 144], 3
	movzx	edx, byte ptr [rsp + 143]
	mov	eax, edx
	mov	qword ptr [rsp + 296], rax
	mov	dword ptr [rsp + 292], 3
	mov	dword ptr [rsp + 288], 2
	mov	edx, dword ptr [rsp + 292]
	mov	eax, edx
	cmp	rax, 64
	setb	sil
	xor	sil, -1
	test	sil, 1
	jne	LBB0_48
	jmp	LBB0_49
LBB0_48:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 478
	call	___assert_rtn
LBB0_49:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 288], 0
	mov	byte ptr [rsp + 60], cl ## 1-byte Spill
	jbe	LBB0_51
## %bb.50:
	mov	eax, dword ptr [rsp + 288]
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	mov	byte ptr [rsp + 60], dl ## 1-byte Spill
LBB0_51:
	mov	al, byte ptr [rsp + 60] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_52
	jmp	LBB0_53
LBB0_52:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 479
	call	___assert_rtn
LBB0_53:
	mov	eax, dword ptr [rsp + 292]
	add	eax, dword ptr [rsp + 288]
	mov	eax, eax
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_54
	jmp	LBB0_55
LBB0_54:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 480
	call	___assert_rtn
LBB0_55:
	mov	eax, dword ptr [rsp + 288]
	mov	ecx, eax
	cmp	rcx, 64
	jne	LBB0_57
## %bb.56:
	mov	rax, qword ptr [rsp + 296]
	mov	qword ptr [rsp + 304], rax
	jmp	LBB0_58
LBB0_57:
	mov	rax, qword ptr [rsp + 296]
	mov	ecx, dword ptr [rsp + 292]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, dword ptr [rsp + 288]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	mov	esi, 1
	shl	rsi, cl
	sub	rsi, 1
	and	rax, rsi
	mov	qword ptr [rsp + 304], rax
LBB0_58:
	mov	rax, qword ptr [rsp + 304]
	mov	qword ptr [rsp + 152], rax
	mov	rax, qword ptr [rsp + 200]
	mov	rcx, qword ptr [rsp + 144]
	add	rcx, qword ptr [rsp + 152]
	cmp	rax, rcx
	ja	LBB0_60
## %bb.59:
	jmp	LBB0_247
LBB0_60:
	mov	rax, qword ptr [rsp + 184]
	add	rax, 1
	mov	qword ptr [rsp + 320], rax
	mov	rax, qword ptr [rsp + 320]
	mov	cx, word ptr [rax]
	mov	word ptr [rsp + 318], cx
	mov	cx, word ptr [rsp + 318]
	mov	word ptr [rsp + 140], cx
	movzx	edx, byte ptr [rsp + 143]
	mov	eax, edx
	mov	qword ptr [rsp + 336], rax
	mov	dword ptr [rsp + 332], 0
	mov	dword ptr [rsp + 328], 3
	mov	edx, dword ptr [rsp + 332]
	mov	eax, edx
	cmp	rax, 64
	setb	sil
	xor	sil, -1
	test	sil, 1
	jne	LBB0_61
	jmp	LBB0_62
LBB0_61:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 478
	call	___assert_rtn
LBB0_62:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 328], 0
	mov	byte ptr [rsp + 59], cl ## 1-byte Spill
	jbe	LBB0_64
## %bb.63:
	mov	eax, dword ptr [rsp + 328]
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	mov	byte ptr [rsp + 59], dl ## 1-byte Spill
LBB0_64:
	mov	al, byte ptr [rsp + 59] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_65
	jmp	LBB0_66
LBB0_65:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 479
	call	___assert_rtn
LBB0_66:
	mov	eax, dword ptr [rsp + 332]
	add	eax, dword ptr [rsp + 328]
	mov	eax, eax
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_67
	jmp	LBB0_68
LBB0_67:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 480
	call	___assert_rtn
LBB0_68:
	mov	eax, dword ptr [rsp + 328]
	mov	ecx, eax
	cmp	rcx, 64
	jne	LBB0_70
## %bb.69:
	mov	rax, qword ptr [rsp + 336]
	mov	qword ptr [rsp + 344], rax
	jmp	LBB0_71
LBB0_70:
	mov	rax, qword ptr [rsp + 336]
	mov	ecx, dword ptr [rsp + 332]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, dword ptr [rsp + 328]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	mov	esi, 1
	shl	rsi, cl
	sub	rsi, 1
	and	rax, rsi
	mov	qword ptr [rsp + 344], rax
LBB0_71:
	mov	rax, qword ptr [rsp + 344]
	shl	rax, 2
	movzx	ecx, word ptr [rsp + 140]
	mov	edx, ecx
	mov	qword ptr [rsp + 360], rdx
	mov	dword ptr [rsp + 356], 0
	mov	dword ptr [rsp + 352], 2
	mov	ecx, dword ptr [rsp + 356]
	mov	edx, ecx
	cmp	rdx, 64
	setb	sil
	xor	sil, -1
	test	sil, 1
	mov	qword ptr [rsp + 48], rax ## 8-byte Spill
	jne	LBB0_72
	jmp	LBB0_73
LBB0_72:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 478
	call	___assert_rtn
LBB0_73:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 352], 0
	mov	byte ptr [rsp + 47], cl ## 1-byte Spill
	jbe	LBB0_75
## %bb.74:
	mov	eax, dword ptr [rsp + 352]
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	mov	byte ptr [rsp + 47], dl ## 1-byte Spill
LBB0_75:
	mov	al, byte ptr [rsp + 47] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_76
	jmp	LBB0_77
LBB0_76:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 479
	call	___assert_rtn
LBB0_77:
	mov	eax, dword ptr [rsp + 356]
	add	eax, dword ptr [rsp + 352]
	mov	eax, eax
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_78
	jmp	LBB0_79
LBB0_78:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 480
	call	___assert_rtn
LBB0_79:
	mov	eax, dword ptr [rsp + 352]
	mov	ecx, eax
	cmp	rcx, 64
	jne	LBB0_81
## %bb.80:
	mov	rax, qword ptr [rsp + 360]
	mov	qword ptr [rsp + 368], rax
	jmp	LBB0_82
LBB0_81:
	mov	rax, qword ptr [rsp + 360]
	mov	ecx, dword ptr [rsp + 356]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, dword ptr [rsp + 352]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	mov	esi, 1
	shl	rsi, cl
	sub	rsi, 1
	and	rax, rsi
	mov	qword ptr [rsp + 368], rax
LBB0_82:
	mov	rax, qword ptr [rsp + 48] ## 8-byte Reload
	or	rax, qword ptr [rsp + 368]
	add	rax, 3
	mov	qword ptr [rsp + 160], rax
	movzx	ecx, word ptr [rsp + 140]
	mov	eax, ecx
	mov	qword ptr [rsp + 384], rax
	mov	dword ptr [rsp + 380], 2
	mov	dword ptr [rsp + 376], 14
	mov	ecx, dword ptr [rsp + 380]
	mov	eax, ecx
	cmp	rax, 64
	setb	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_83
	jmp	LBB0_84
LBB0_83:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 478
	call	___assert_rtn
LBB0_84:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 376], 0
	mov	byte ptr [rsp + 46], cl ## 1-byte Spill
	jbe	LBB0_86
## %bb.85:
	mov	eax, dword ptr [rsp + 376]
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	mov	byte ptr [rsp + 46], dl ## 1-byte Spill
LBB0_86:
	mov	al, byte ptr [rsp + 46] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_87
	jmp	LBB0_88
LBB0_87:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 479
	call	___assert_rtn
LBB0_88:
	mov	eax, dword ptr [rsp + 380]
	add	eax, dword ptr [rsp + 376]
	mov	eax, eax
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_89
	jmp	LBB0_90
LBB0_89:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 480
	call	___assert_rtn
LBB0_90:
	mov	eax, dword ptr [rsp + 376]
	mov	ecx, eax
	cmp	rcx, 64
	jne	LBB0_92
## %bb.91:
	mov	rax, qword ptr [rsp + 384]
	mov	qword ptr [rsp + 392], rax
	jmp	LBB0_93
LBB0_92:
	mov	rax, qword ptr [rsp + 384]
	mov	ecx, dword ptr [rsp + 380]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, dword ptr [rsp + 376]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	mov	esi, 1
	shl	rsi, cl
	sub	rsi, 1
	and	rax, rsi
	mov	qword ptr [rsp + 392], rax
LBB0_93:
	mov	rax, qword ptr [rsp + 392]
	mov	qword ptr [rsp + 168], rax
	jmp	LBB0_144
Ltmp2:                                  ## Block address taken
LBB0_94:
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 16], rax
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 72], rax
	mov	qword ptr [rsp + 144], 3
	movzx	edx, byte ptr [rsp + 143]
	mov	eax, edx
	mov	qword ptr [rsp + 408], rax
	mov	dword ptr [rsp + 404], 6
	mov	dword ptr [rsp + 400], 2
	mov	edx, dword ptr [rsp + 404]
	mov	eax, edx
	cmp	rax, 64
	setb	sil
	xor	sil, -1
	test	sil, 1
	jne	LBB0_95
	jmp	LBB0_96
LBB0_95:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 478
	call	___assert_rtn
LBB0_96:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 400], 0
	mov	byte ptr [rsp + 45], cl ## 1-byte Spill
	jbe	LBB0_98
## %bb.97:
	mov	eax, dword ptr [rsp + 400]
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	mov	byte ptr [rsp + 45], dl ## 1-byte Spill
LBB0_98:
	mov	al, byte ptr [rsp + 45] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_99
	jmp	LBB0_100
LBB0_99:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 479
	call	___assert_rtn
LBB0_100:
	mov	eax, dword ptr [rsp + 404]
	add	eax, dword ptr [rsp + 400]
	mov	eax, eax
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_101
	jmp	LBB0_102
LBB0_101:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 480
	call	___assert_rtn
LBB0_102:
	mov	eax, dword ptr [rsp + 400]
	mov	ecx, eax
	cmp	rcx, 64
	jne	LBB0_104
## %bb.103:
	mov	rax, qword ptr [rsp + 408]
	mov	qword ptr [rsp + 416], rax
	jmp	LBB0_105
LBB0_104:
	mov	rax, qword ptr [rsp + 408]
	mov	ecx, dword ptr [rsp + 404]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, dword ptr [rsp + 400]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	mov	esi, 1
	shl	rsi, cl
	sub	rsi, 1
	and	rax, rsi
	mov	qword ptr [rsp + 416], rax
LBB0_105:
	mov	rax, qword ptr [rsp + 416]
	mov	qword ptr [rsp + 152], rax
	movzx	ecx, byte ptr [rsp + 143]
	mov	eax, ecx
	mov	qword ptr [rsp + 432], rax
	mov	dword ptr [rsp + 428], 3
	mov	dword ptr [rsp + 424], 3
	mov	ecx, dword ptr [rsp + 428]
	mov	eax, ecx
	cmp	rax, 64
	setb	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_106
	jmp	LBB0_107
LBB0_106:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 478
	call	___assert_rtn
LBB0_107:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 424], 0
	mov	byte ptr [rsp + 44], cl ## 1-byte Spill
	jbe	LBB0_109
## %bb.108:
	mov	eax, dword ptr [rsp + 424]
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	mov	byte ptr [rsp + 44], dl ## 1-byte Spill
LBB0_109:
	mov	al, byte ptr [rsp + 44] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_110
	jmp	LBB0_111
LBB0_110:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 479
	call	___assert_rtn
LBB0_111:
	mov	eax, dword ptr [rsp + 428]
	add	eax, dword ptr [rsp + 424]
	mov	eax, eax
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_112
	jmp	LBB0_113
LBB0_112:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 480
	call	___assert_rtn
LBB0_113:
	mov	eax, dword ptr [rsp + 424]
	mov	ecx, eax
	cmp	rcx, 64
	jne	LBB0_115
## %bb.114:
	mov	rax, qword ptr [rsp + 432]
	mov	qword ptr [rsp + 440], rax
	jmp	LBB0_116
LBB0_115:
	mov	rax, qword ptr [rsp + 432]
	mov	ecx, dword ptr [rsp + 428]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, dword ptr [rsp + 424]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	mov	esi, 1
	shl	rsi, cl
	sub	rsi, 1
	and	rax, rsi
	mov	qword ptr [rsp + 440], rax
LBB0_116:
	mov	rax, qword ptr [rsp + 440]
	add	rax, 3
	mov	qword ptr [rsp + 160], rax
	mov	rax, qword ptr [rsp + 200]
	mov	rcx, qword ptr [rsp + 144]
	add	rcx, qword ptr [rsp + 152]
	cmp	rax, rcx
	ja	LBB0_118
## %bb.117:
	jmp	LBB0_247
LBB0_118:
	mov	rax, qword ptr [rsp + 184]
	add	rax, 1
	mov	qword ptr [rsp + 456], rax
	mov	rax, qword ptr [rsp + 456]
	mov	cx, word ptr [rax]
	mov	word ptr [rsp + 454], cx
	movzx	edx, word ptr [rsp + 454]
	mov	eax, edx
	mov	qword ptr [rsp + 168], rax
	jmp	LBB0_144
Ltmp3:                                  ## Block address taken
LBB0_119:
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 16], rax
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 72], rax
	mov	qword ptr [rsp + 144], 1
	movzx	edx, byte ptr [rsp + 143]
	mov	eax, edx
	mov	qword ptr [rsp + 472], rax
	mov	dword ptr [rsp + 468], 6
	mov	dword ptr [rsp + 464], 2
	mov	edx, dword ptr [rsp + 468]
	mov	eax, edx
	cmp	rax, 64
	setb	sil
	xor	sil, -1
	test	sil, 1
	jne	LBB0_120
	jmp	LBB0_121
LBB0_120:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 478
	call	___assert_rtn
LBB0_121:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 464], 0
	mov	byte ptr [rsp + 43], cl ## 1-byte Spill
	jbe	LBB0_123
## %bb.122:
	mov	eax, dword ptr [rsp + 464]
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	mov	byte ptr [rsp + 43], dl ## 1-byte Spill
LBB0_123:
	mov	al, byte ptr [rsp + 43] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_124
	jmp	LBB0_125
LBB0_124:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 479
	call	___assert_rtn
LBB0_125:
	mov	eax, dword ptr [rsp + 468]
	add	eax, dword ptr [rsp + 464]
	mov	eax, eax
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_126
	jmp	LBB0_127
LBB0_126:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 480
	call	___assert_rtn
LBB0_127:
	mov	eax, dword ptr [rsp + 464]
	mov	ecx, eax
	cmp	rcx, 64
	jne	LBB0_129
## %bb.128:
	mov	rax, qword ptr [rsp + 472]
	mov	qword ptr [rsp + 480], rax
	jmp	LBB0_130
LBB0_129:
	mov	rax, qword ptr [rsp + 472]
	mov	ecx, dword ptr [rsp + 468]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, dword ptr [rsp + 464]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	mov	esi, 1
	shl	rsi, cl
	sub	rsi, 1
	and	rax, rsi
	mov	qword ptr [rsp + 480], rax
LBB0_130:
	mov	rax, qword ptr [rsp + 480]
	mov	qword ptr [rsp + 152], rax
	movzx	ecx, byte ptr [rsp + 143]
	mov	eax, ecx
	mov	qword ptr [rsp + 496], rax
	mov	dword ptr [rsp + 492], 3
	mov	dword ptr [rsp + 488], 3
	mov	ecx, dword ptr [rsp + 492]
	mov	eax, ecx
	cmp	rax, 64
	setb	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_131
	jmp	LBB0_132
LBB0_131:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 478
	call	___assert_rtn
LBB0_132:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 488], 0
	mov	byte ptr [rsp + 42], cl ## 1-byte Spill
	jbe	LBB0_134
## %bb.133:
	mov	eax, dword ptr [rsp + 488]
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	mov	byte ptr [rsp + 42], dl ## 1-byte Spill
LBB0_134:
	mov	al, byte ptr [rsp + 42] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_135
	jmp	LBB0_136
LBB0_135:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 479
	call	___assert_rtn
LBB0_136:
	mov	eax, dword ptr [rsp + 492]
	add	eax, dword ptr [rsp + 488]
	mov	eax, eax
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_137
	jmp	LBB0_138
LBB0_137:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 480
	call	___assert_rtn
LBB0_138:
	mov	eax, dword ptr [rsp + 488]
	mov	ecx, eax
	cmp	rcx, 64
	jne	LBB0_140
## %bb.139:
	mov	rax, qword ptr [rsp + 496]
	mov	qword ptr [rsp + 504], rax
	jmp	LBB0_141
LBB0_140:
	mov	rax, qword ptr [rsp + 496]
	mov	ecx, dword ptr [rsp + 492]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, dword ptr [rsp + 488]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	mov	esi, 1
	shl	rsi, cl
	sub	rsi, 1
	and	rax, rsi
	mov	qword ptr [rsp + 504], rax
LBB0_141:
	mov	rax, qword ptr [rsp + 504]
	add	rax, 3
	mov	qword ptr [rsp + 160], rax
	mov	rax, qword ptr [rsp + 200]
	mov	rcx, qword ptr [rsp + 144]
	add	rcx, qword ptr [rsp + 152]
	cmp	rax, rcx
	ja	LBB0_143
## %bb.142:
	jmp	LBB0_247
LBB0_143:
	jmp	LBB0_144
LBB0_144:
	xor	eax, eax
	mov	cl, al
	mov	rdx, qword ptr [rsp + 144]
	add	rdx, qword ptr [rsp + 184]
	mov	qword ptr [rsp + 184], rdx
	mov	rdx, qword ptr [rsp + 144]
	mov	rsi, qword ptr [rsp + 200]
	sub	rsi, rdx
	mov	qword ptr [rsp + 200], rsi
	cmp	qword ptr [rsp + 192], 4
	mov	byte ptr [rsp + 41], cl ## 1-byte Spill
	jb	LBB0_146
## %bb.145:
	cmp	qword ptr [rsp + 200], 4
	setae	al
	mov	byte ptr [rsp + 41], al ## 1-byte Spill
LBB0_146:
	mov	al, byte ptr [rsp + 41] ## 1-byte Reload
	and	al, 1
	movzx	ecx, al
	movsxd	rdx, ecx
	cmp	rdx, 0
	je	LBB0_148
## %bb.147:
	mov	rcx, -1
	mov	rax, qword ptr [rsp + 176]
	mov	rdx, qword ptr [rsp + 184]
	mov	qword ptr [rsp + 520], rdx
	mov	rdx, qword ptr [rsp + 520]
	mov	esi, dword ptr [rdx]
	mov	dword ptr [rsp + 516], esi
	mov	esi, dword ptr [rsp + 516]
	mov	qword ptr [rsp + 536], rax
	mov	dword ptr [rsp + 532], esi
	mov	rdi, qword ptr [rsp + 536]
	lea	rax, [rsp + 532]
	mov	rsi, rax
	mov	edx, 4
	call	___memcpy_chk
	mov	qword ptr [rsp + 32], rax ## 8-byte Spill
	jmp	LBB0_160
LBB0_148:
	mov	rax, qword ptr [rsp + 152]
	cmp	rax, qword ptr [rsp + 192]
	ja	LBB0_154
## %bb.149:
	mov	qword ptr [rsp + 128], 0
LBB0_150:                               ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 128]
	cmp	rax, qword ptr [rsp + 152]
	jae	LBB0_153
## %bb.151:                             ##   in Loop: Header=BB0_150 Depth=1
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 128]
	mov	dl, byte ptr [rax + rcx]
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 128]
	mov	byte ptr [rax + rcx], dl
## %bb.152:                             ##   in Loop: Header=BB0_150 Depth=1
	mov	rax, qword ptr [rsp + 128]
	add	rax, 1
	mov	qword ptr [rsp + 128], rax
	jmp	LBB0_150
LBB0_153:
	jmp	LBB0_159
LBB0_154:
	mov	qword ptr [rsp + 120], 0
LBB0_155:                               ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 120]
	cmp	rax, qword ptr [rsp + 192]
	jae	LBB0_158
## %bb.156:                             ##   in Loop: Header=BB0_155 Depth=1
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 120]
	mov	dl, byte ptr [rax + rcx]
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 120]
	mov	byte ptr [rax + rcx], dl
## %bb.157:                             ##   in Loop: Header=BB0_155 Depth=1
	mov	rax, qword ptr [rsp + 120]
	add	rax, 1
	mov	qword ptr [rsp + 120], rax
	jmp	LBB0_155
LBB0_158:
	mov	rax, qword ptr [rsp + 184]
	add	rax, qword ptr [rsp + 192]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 176]
	add	rax, qword ptr [rsp + 192]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 16], rax
	mov	rax, qword ptr [rsp + 152]
	sub	rax, qword ptr [rsp + 192]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 48], rax
	mov	rax, qword ptr [rsp + 160]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 56], rax
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 64], rax
	jmp	LBB0_247
LBB0_159:
	jmp	LBB0_160
LBB0_160:
	mov	rax, qword ptr [rsp + 152]
	add	rax, qword ptr [rsp + 176]
	mov	qword ptr [rsp + 176], rax
	mov	rax, qword ptr [rsp + 152]
	mov	rcx, qword ptr [rsp + 192]
	sub	rcx, rax
	mov	qword ptr [rsp + 192], rcx
	mov	rax, qword ptr [rsp + 152]
	add	rax, qword ptr [rsp + 184]
	mov	qword ptr [rsp + 184], rax
	mov	rax, qword ptr [rsp + 152]
	mov	rcx, qword ptr [rsp + 200]
	sub	rcx, rax
	mov	qword ptr [rsp + 200], rcx
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 176]
	mov	rdx, qword ptr [rsp + 208]
	mov	rdx, qword ptr [rdx + 24]
	sub	rcx, rdx
	cmp	rax, rcx
	ja	LBB0_162
## %bb.161:
	cmp	qword ptr [rsp + 168], 0
	jne	LBB0_163
LBB0_162:
	jmp	LBB0_246
LBB0_163:
	jmp	LBB0_164
LBB0_164:
	xor	eax, eax
	mov	cl, al
	mov	rdx, qword ptr [rsp + 192]
	mov	rsi, qword ptr [rsp + 160]
	add	rsi, 7
	cmp	rdx, rsi
	mov	byte ptr [rsp + 31], cl ## 1-byte Spill
	jb	LBB0_166
## %bb.165:
	cmp	qword ptr [rsp + 168], 8
	setae	al
	mov	byte ptr [rsp + 31], al ## 1-byte Spill
LBB0_166:
	mov	al, byte ptr [rsp + 31] ## 1-byte Reload
	and	al, 1
	movzx	ecx, al
	movsxd	rdx, ecx
	cmp	rdx, 0
	je	LBB0_172
## %bb.167:
	mov	qword ptr [rsp + 112], 0
LBB0_168:                               ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 112]
	cmp	rax, qword ptr [rsp + 160]
	jae	LBB0_171
## %bb.169:                             ##   in Loop: Header=BB0_168 Depth=1
	mov	rcx, -1
	mov	rax, qword ptr [rsp + 176]
	add	rax, qword ptr [rsp + 112]
	mov	rdx, qword ptr [rsp + 176]
	mov	rsi, qword ptr [rsp + 112]
	sub	rsi, qword ptr [rsp + 168]
	add	rdx, rsi
	mov	qword ptr [rsp + 552], rdx
	mov	rdx, qword ptr [rsp + 552]
	mov	rdx, qword ptr [rdx]
	mov	qword ptr [rsp + 544], rdx
	mov	rdx, qword ptr [rsp + 544]
	mov	qword ptr [rsp + 568], rax
	mov	qword ptr [rsp + 560], rdx
	mov	rdi, qword ptr [rsp + 568]
	lea	rax, [rsp + 560]
	mov	rsi, rax
	mov	edx, 8
	call	___memcpy_chk
	mov	qword ptr [rsp + 16], rax ## 8-byte Spill
## %bb.170:                             ##   in Loop: Header=BB0_168 Depth=1
	mov	rax, qword ptr [rsp + 112]
	add	rax, 8
	mov	qword ptr [rsp + 112], rax
	jmp	LBB0_168
LBB0_171:
	jmp	LBB0_184
LBB0_172:
	mov	rax, qword ptr [rsp + 160]
	cmp	rax, qword ptr [rsp + 192]
	ja	LBB0_178
## %bb.173:
	mov	qword ptr [rsp + 104], 0
LBB0_174:                               ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 104]
	cmp	rax, qword ptr [rsp + 160]
	jae	LBB0_177
## %bb.175:                             ##   in Loop: Header=BB0_174 Depth=1
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 104]
	sub	rcx, qword ptr [rsp + 168]
	mov	dl, byte ptr [rax + rcx]
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 104]
	mov	byte ptr [rax + rcx], dl
## %bb.176:                             ##   in Loop: Header=BB0_174 Depth=1
	mov	rax, qword ptr [rsp + 104]
	add	rax, 1
	mov	qword ptr [rsp + 104], rax
	jmp	LBB0_174
LBB0_177:
	jmp	LBB0_183
LBB0_178:
	mov	qword ptr [rsp + 96], 0
LBB0_179:                               ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 96]
	cmp	rax, qword ptr [rsp + 192]
	jae	LBB0_182
## %bb.180:                             ##   in Loop: Header=BB0_179 Depth=1
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 96]
	sub	rcx, qword ptr [rsp + 168]
	mov	dl, byte ptr [rax + rcx]
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 96]
	mov	byte ptr [rax + rcx], dl
## %bb.181:                             ##   in Loop: Header=BB0_179 Depth=1
	mov	rax, qword ptr [rsp + 96]
	add	rax, 1
	mov	qword ptr [rsp + 96], rax
	jmp	LBB0_179
LBB0_182:
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 176]
	add	rax, qword ptr [rsp + 192]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 16], rax
	mov	rax, qword ptr [rsp + 208]
	mov	qword ptr [rax + 48], 0
	mov	rax, qword ptr [rsp + 160]
	sub	rax, qword ptr [rsp + 192]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 56], rax
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 64], rax
	jmp	LBB0_247
LBB0_183:
	jmp	LBB0_184
LBB0_184:
	mov	rax, qword ptr [rsp + 160]
	add	rax, qword ptr [rsp + 176]
	mov	qword ptr [rsp + 176], rax
	mov	rax, qword ptr [rsp + 160]
	mov	rcx, qword ptr [rsp + 192]
	sub	rcx, rax
	mov	qword ptr [rsp + 192], rcx
	mov	rax, qword ptr [rsp + 184]
	mov	dl, byte ptr [rax]
	mov	byte ptr [rsp + 143], dl
	movzx	esi, byte ptr [rsp + 143]
	mov	eax, esi
	lea	rcx, [rip + _lzvn_decode.opc_tbl]
	mov	rax, qword ptr [rcx + 8*rax]
	mov	qword ptr [rsp + 64], rax ## 8-byte Spill
	jmp	LBB0_248
Ltmp4:                                  ## Block address taken
LBB0_185:
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 16], rax
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 72], rax
	mov	qword ptr [rsp + 144], 1
	mov	rax, qword ptr [rsp + 200]
	cmp	rax, qword ptr [rsp + 144]
	ja	LBB0_187
## %bb.186:
	jmp	LBB0_247
LBB0_187:
	movzx	eax, byte ptr [rsp + 143]
	mov	ecx, eax
	mov	qword ptr [rsp + 584], rcx
	mov	dword ptr [rsp + 580], 0
	mov	dword ptr [rsp + 576], 4
	mov	eax, dword ptr [rsp + 580]
	mov	ecx, eax
	cmp	rcx, 64
	setb	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_188
	jmp	LBB0_189
LBB0_188:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 478
	call	___assert_rtn
LBB0_189:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 576], 0
	mov	byte ptr [rsp + 15], cl ## 1-byte Spill
	jbe	LBB0_191
## %bb.190:
	mov	eax, dword ptr [rsp + 576]
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	mov	byte ptr [rsp + 15], dl ## 1-byte Spill
LBB0_191:
	mov	al, byte ptr [rsp + 15] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_192
	jmp	LBB0_193
LBB0_192:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 479
	call	___assert_rtn
LBB0_193:
	mov	eax, dword ptr [rsp + 580]
	add	eax, dword ptr [rsp + 576]
	mov	eax, eax
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_194
	jmp	LBB0_195
LBB0_194:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 480
	call	___assert_rtn
LBB0_195:
	mov	eax, dword ptr [rsp + 576]
	mov	ecx, eax
	cmp	rcx, 64
	jne	LBB0_197
## %bb.196:
	mov	rax, qword ptr [rsp + 584]
	mov	qword ptr [rsp + 592], rax
	jmp	LBB0_198
LBB0_197:
	mov	rax, qword ptr [rsp + 584]
	mov	ecx, dword ptr [rsp + 580]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, dword ptr [rsp + 576]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	mov	esi, 1
	shl	rsi, cl
	sub	rsi, 1
	and	rax, rsi
	mov	qword ptr [rsp + 592], rax
LBB0_198:
	mov	rax, qword ptr [rsp + 592]
	mov	qword ptr [rsp + 160], rax
	mov	rax, qword ptr [rsp + 144]
	add	rax, qword ptr [rsp + 184]
	mov	qword ptr [rsp + 184], rax
	mov	rax, qword ptr [rsp + 144]
	mov	rcx, qword ptr [rsp + 200]
	sub	rcx, rax
	mov	qword ptr [rsp + 200], rcx
	jmp	LBB0_164
Ltmp5:                                  ## Block address taken
LBB0_199:
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 16], rax
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 72], rax
	mov	qword ptr [rsp + 144], 2
	mov	rax, qword ptr [rsp + 200]
	cmp	rax, qword ptr [rsp + 144]
	ja	LBB0_201
## %bb.200:
	jmp	LBB0_247
LBB0_201:
	mov	rax, qword ptr [rsp + 184]
	movzx	ecx, byte ptr [rax + 1]
	add	ecx, 16
	movsxd	rax, ecx
	mov	qword ptr [rsp + 160], rax
	mov	rax, qword ptr [rsp + 144]
	add	rax, qword ptr [rsp + 184]
	mov	qword ptr [rsp + 184], rax
	mov	rax, qword ptr [rsp + 144]
	mov	rdx, qword ptr [rsp + 200]
	sub	rdx, rax
	mov	qword ptr [rsp + 200], rdx
	jmp	LBB0_164
Ltmp6:                                  ## Block address taken
LBB0_202:
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 16], rax
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 72], rax
	mov	qword ptr [rsp + 144], 1
	movzx	edx, byte ptr [rsp + 143]
	mov	eax, edx
	mov	qword ptr [rsp + 608], rax
	mov	dword ptr [rsp + 604], 0
	mov	dword ptr [rsp + 600], 4
	mov	edx, dword ptr [rsp + 604]
	mov	eax, edx
	cmp	rax, 64
	setb	sil
	xor	sil, -1
	test	sil, 1
	jne	LBB0_203
	jmp	LBB0_204
LBB0_203:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.1]
	mov	edx, 478
	call	___assert_rtn
LBB0_204:
	xor	eax, eax
	mov	cl, al
	cmp	dword ptr [rsp + 600], 0
	mov	byte ptr [rsp + 14], cl ## 1-byte Spill
	jbe	LBB0_206
## %bb.205:
	mov	eax, dword ptr [rsp + 600]
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	mov	byte ptr [rsp + 14], dl ## 1-byte Spill
LBB0_206:
	mov	al, byte ptr [rsp + 14] ## 1-byte Reload
	xor	al, -1
	test	al, 1
	jne	LBB0_207
	jmp	LBB0_208
LBB0_207:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.2]
	mov	edx, 479
	call	___assert_rtn
LBB0_208:
	mov	eax, dword ptr [rsp + 604]
	add	eax, dword ptr [rsp + 600]
	mov	eax, eax
	mov	ecx, eax
	cmp	rcx, 64
	setbe	dl
	xor	dl, -1
	test	dl, 1
	jne	LBB0_209
	jmp	LBB0_210
LBB0_209:
	lea	rdi, [rip + L___func__.extract]
	lea	rsi, [rip + L_.str]
	lea	rcx, [rip + L_.str.3]
	mov	edx, 480
	call	___assert_rtn
LBB0_210:
	mov	eax, dword ptr [rsp + 600]
	mov	ecx, eax
	cmp	rcx, 64
	jne	LBB0_212
## %bb.211:
	mov	rax, qword ptr [rsp + 608]
	mov	qword ptr [rsp + 616], rax
	jmp	LBB0_213
LBB0_212:
	mov	rax, qword ptr [rsp + 608]
	mov	ecx, dword ptr [rsp + 604]
                                        ## kill: def $rcx killed $ecx
                                        ## kill: def $cl killed $rcx
	shr	rax, cl
	mov	edx, dword ptr [rsp + 600]
	mov	ecx, edx
                                        ## kill: def $cl killed $rcx
	mov	esi, 1
	shl	rsi, cl
	sub	rsi, 1
	and	rax, rsi
	mov	qword ptr [rsp + 616], rax
LBB0_213:
	mov	rax, qword ptr [rsp + 616]
	mov	qword ptr [rsp + 152], rax
	jmp	LBB0_217
Ltmp7:                                  ## Block address taken
LBB0_214:
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 16], rax
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 72], rax
	mov	qword ptr [rsp + 144], 2
	cmp	qword ptr [rsp + 200], 2
	ja	LBB0_216
## %bb.215:
	jmp	LBB0_247
LBB0_216:
	mov	rax, qword ptr [rsp + 184]
	movzx	ecx, byte ptr [rax + 1]
	add	ecx, 16
	movsxd	rax, ecx
	mov	qword ptr [rsp + 152], rax
LBB0_217:
	mov	rax, qword ptr [rsp + 200]
	mov	rcx, qword ptr [rsp + 144]
	add	rcx, qword ptr [rsp + 152]
	cmp	rax, rcx
	ja	LBB0_219
## %bb.218:
	jmp	LBB0_247
LBB0_219:
	mov	rax, qword ptr [rsp + 144]
	add	rax, qword ptr [rsp + 184]
	mov	qword ptr [rsp + 184], rax
	mov	rax, qword ptr [rsp + 144]
	mov	rcx, qword ptr [rsp + 200]
	sub	rcx, rax
	mov	qword ptr [rsp + 200], rcx
	mov	rax, qword ptr [rsp + 192]
	mov	rcx, qword ptr [rsp + 152]
	add	rcx, 7
	cmp	rax, rcx
	jb	LBB0_226
## %bb.220:
	mov	rax, qword ptr [rsp + 200]
	mov	rcx, qword ptr [rsp + 152]
	add	rcx, 7
	cmp	rax, rcx
	jb	LBB0_226
## %bb.221:
	mov	qword ptr [rsp + 88], 0
LBB0_222:                               ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 88]
	cmp	rax, qword ptr [rsp + 152]
	jae	LBB0_225
## %bb.223:                             ##   in Loop: Header=BB0_222 Depth=1
	mov	rcx, -1
	mov	rax, qword ptr [rsp + 176]
	add	rax, qword ptr [rsp + 88]
	mov	rdx, qword ptr [rsp + 184]
	add	rdx, qword ptr [rsp + 88]
	mov	qword ptr [rsp + 632], rdx
	mov	rdx, qword ptr [rsp + 632]
	mov	rdx, qword ptr [rdx]
	mov	qword ptr [rsp + 624], rdx
	mov	rdx, qword ptr [rsp + 624]
	mov	qword ptr [rsp + 648], rax
	mov	qword ptr [rsp + 640], rdx
	mov	rdi, qword ptr [rsp + 648]
	lea	rax, [rsp + 640]
	mov	rsi, rax
	mov	edx, 8
	call	___memcpy_chk
	mov	qword ptr [rsp], rax    ## 8-byte Spill
## %bb.224:                             ##   in Loop: Header=BB0_222 Depth=1
	mov	rax, qword ptr [rsp + 88]
	add	rax, 8
	mov	qword ptr [rsp + 88], rax
	jmp	LBB0_222
LBB0_225:
	jmp	LBB0_238
LBB0_226:
	mov	rax, qword ptr [rsp + 152]
	cmp	rax, qword ptr [rsp + 192]
	ja	LBB0_232
## %bb.227:
	mov	qword ptr [rsp + 80], 0
LBB0_228:                               ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 80]
	cmp	rax, qword ptr [rsp + 152]
	jae	LBB0_231
## %bb.229:                             ##   in Loop: Header=BB0_228 Depth=1
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 80]
	mov	dl, byte ptr [rax + rcx]
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 80]
	mov	byte ptr [rax + rcx], dl
## %bb.230:                             ##   in Loop: Header=BB0_228 Depth=1
	mov	rax, qword ptr [rsp + 80]
	add	rax, 1
	mov	qword ptr [rsp + 80], rax
	jmp	LBB0_228
LBB0_231:
	jmp	LBB0_237
LBB0_232:
	mov	qword ptr [rsp + 72], 0
LBB0_233:                               ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 72]
	cmp	rax, qword ptr [rsp + 192]
	jae	LBB0_236
## %bb.234:                             ##   in Loop: Header=BB0_233 Depth=1
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 72]
	mov	dl, byte ptr [rax + rcx]
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 72]
	mov	byte ptr [rax + rcx], dl
## %bb.235:                             ##   in Loop: Header=BB0_233 Depth=1
	mov	rax, qword ptr [rsp + 72]
	add	rax, 1
	mov	qword ptr [rsp + 72], rax
	jmp	LBB0_233
LBB0_236:
	mov	rax, qword ptr [rsp + 184]
	add	rax, qword ptr [rsp + 192]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 176]
	add	rax, qword ptr [rsp + 192]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 16], rax
	mov	rax, qword ptr [rsp + 152]
	sub	rax, qword ptr [rsp + 192]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 48], rax
	mov	rax, qword ptr [rsp + 208]
	mov	qword ptr [rax + 56], 0
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 64], rax
	jmp	LBB0_247
LBB0_237:
	jmp	LBB0_238
LBB0_238:
	mov	rax, qword ptr [rsp + 152]
	add	rax, qword ptr [rsp + 176]
	mov	qword ptr [rsp + 176], rax
	mov	rax, qword ptr [rsp + 152]
	mov	rcx, qword ptr [rsp + 192]
	sub	rcx, rax
	mov	qword ptr [rsp + 192], rcx
	mov	rax, qword ptr [rsp + 152]
	add	rax, qword ptr [rsp + 184]
	mov	qword ptr [rsp + 184], rax
	mov	rax, qword ptr [rsp + 152]
	mov	rcx, qword ptr [rsp + 200]
	sub	rcx, rax
	mov	qword ptr [rsp + 200], rcx
	mov	rax, qword ptr [rsp + 184]
	mov	dl, byte ptr [rax]
	mov	byte ptr [rsp + 143], dl
	movzx	esi, byte ptr [rsp + 143]
	mov	eax, esi
	lea	rcx, [rip + _lzvn_decode.opc_tbl]
	mov	rax, qword ptr [rcx + 8*rax]
	mov	qword ptr [rsp + 64], rax ## 8-byte Spill
	jmp	LBB0_248
Ltmp8:                                  ## Block address taken
LBB0_239:                               ##   in Loop: Header=BB0_248 Depth=1
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 16], rax
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 72], rax
	mov	qword ptr [rsp + 144], 1
	mov	rax, qword ptr [rsp + 200]
	cmp	rax, qword ptr [rsp + 144]
	ja	LBB0_241
## %bb.240:
	jmp	LBB0_247
LBB0_241:                               ##   in Loop: Header=BB0_248 Depth=1
	mov	rax, qword ptr [rsp + 144]
	add	rax, qword ptr [rsp + 184]
	mov	qword ptr [rsp + 184], rax
	mov	rax, qword ptr [rsp + 144]
	mov	rcx, qword ptr [rsp + 200]
	sub	rcx, rax
	mov	qword ptr [rsp + 200], rcx
	mov	rax, qword ptr [rsp + 184]
	mov	dl, byte ptr [rax]
	mov	byte ptr [rsp + 143], dl
	movzx	esi, byte ptr [rsp + 143]
	mov	eax, esi
	lea	rcx, [rip + _lzvn_decode.opc_tbl]
	mov	rax, qword ptr [rcx + 8*rax]
	mov	qword ptr [rsp + 64], rax ## 8-byte Spill
	jmp	LBB0_248
Ltmp9:                                  ## Block address taken
LBB0_242:
	mov	qword ptr [rsp + 144], 8
	mov	rax, qword ptr [rsp + 200]
	cmp	rax, qword ptr [rsp + 144]
	jae	LBB0_244
## %bb.243:
	jmp	LBB0_247
LBB0_244:
	mov	rax, qword ptr [rsp + 144]
	add	rax, qword ptr [rsp + 184]
	mov	qword ptr [rsp + 184], rax
	mov	rax, qword ptr [rsp + 144]
	mov	rcx, qword ptr [rsp + 200]
	sub	rcx, rax
	mov	qword ptr [rsp + 200], rcx
	mov	rax, qword ptr [rsp + 208]
	mov	dword ptr [rax + 80], 1
	mov	rax, qword ptr [rsp + 184]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx], rax
	mov	rax, qword ptr [rsp + 176]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 16], rax
	mov	rax, qword ptr [rsp + 168]
	mov	rcx, qword ptr [rsp + 208]
	mov	qword ptr [rcx + 72], rax
	jmp	LBB0_247
Ltmp10:                                 ## Block address taken
LBB0_245:
	jmp	LBB0_246
LBB0_246:
	jmp	LBB0_247
LBB0_247:
	mov	rsp, rbp
	pop	rbp
	ret
LBB0_248:                               ## =>This Inner Loop Header: Depth=1
	mov	rax, qword ptr [rsp + 64] ## 8-byte Reload
	jmp	rax
                                        ## -- End function
	.section	__DATA,__data
	.p2align	4               ## @lzvn_decode.opc_tbl
_lzvn_decode.opc_tbl:
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp9
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp8
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp8
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp10
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp10
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp10
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp10
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp10
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp3
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp3
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp3
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp3
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp3
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp3
	.quad	Ltmp2
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp3
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp3
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp3
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp3
	.quad	Ltmp2
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp1
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp3
	.quad	Ltmp2
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp0
	.quad	Ltmp3
	.quad	Ltmp2
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp10
	.quad	Ltmp7
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp6
	.quad	Ltmp5
	.quad	Ltmp4
	.quad	Ltmp4
	.quad	Ltmp4
	.quad	Ltmp4
	.quad	Ltmp4
	.quad	Ltmp4
	.quad	Ltmp4
	.quad	Ltmp4
	.quad	Ltmp4
	.quad	Ltmp4
	.quad	Ltmp4
	.quad	Ltmp4
	.quad	Ltmp4
	.quad	Ltmp4
	.quad	Ltmp4

	.section	__TEXT,__const
	.p2align	3               ## @extract.container_width
_extract.container_width:
	.quad	64                      ## 0x40

	.section	__TEXT,__cstring,cstring_literals
L___func__.extract:                     ## @__func__.extract
	.asciz	"extract"

L_.str:                                 ## @.str
	.asciz	"/Users/blacktop/Downloads/lzfse-master/src/lzfse_internal.h"

L_.str.1:                               ## @.str.1
	.asciz	"lsb < container_width"

L_.str.2:                               ## @.str.2
	.asciz	"width > 0 && width <= container_width"

L_.str.3:                               ## @.str.3
	.asciz	"lsb + width <= container_width"


.subsections_via_symbols
