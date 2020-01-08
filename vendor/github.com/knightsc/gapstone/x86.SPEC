****************
Platform: X86 16bit (Intel syntax)
Code:0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00 0x05 0x23 0x01 0x00 0x00 0x36 0x8b 0x84 0x91 0x23 0x01 0x00 0x00 0x41 0x8d 0x84 0x39 0x89 0x67 0x00 0x00 0x8d 0x87 0x89 0x67 0x00 0x00 0xb4 0xc6 0x66 0xe9 0xb8 0x00 0x00 0x00 0x67 0xff 0xa0 0x23 0x01 0x00 0x00 0x66 0xe8 0xcb 0x00 0x00 0x00 0x74 0xfc 
Disasm:
0x1000:	lea	cx, [si + 0x32]
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x8d 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x4c
	modrm_offset: 0x1
	disp: 0x32
	disp_offset: 0x2
	disp_size: 0x1
	op_count: 2
		operands[0].type: REG = cx
		operands[0].size: 2
		operands[0].access: WRITE
		operands[1].type: MEM
			operands[1].mem.base: REG = si
			operands[1].mem.disp: 0x32
		operands[1].size: 2
		operands[1].access: READ
	Registers read: si
	Registers modified: cx

0x1003:	or	byte ptr [bx + di], al
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x08 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x1
	modrm_offset: 0x1
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = di
		operands[0].size: 1
		operands[0].access: READ | WRITE
		operands[1].type: REG = al
		operands[1].size: 1
		operands[1].access: READ
	Registers read: bx di al
	Registers modified: flags
	EFLAGS: MOD_SF MOD_ZF MOD_PF RESET_OF RESET_CF UNDEF_AF

0x1005:	fadd	dword ptr [bx + di + 0x34c6]
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0xd8 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x81
	modrm_offset: 0x1
	disp: 0x34c6
	disp_offset: 0x2
	disp_size: 0x2
	op_count: 1
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = di
			operands[0].mem.disp: 0x34c6
		operands[0].size: 4
		operands[0].access: READ
	Registers read: bx di
	Registers modified: fpsw
	FPU_FLAGS: MOD_C1 UNDEF_C0 UNDEF_C2 UNDEF_C3

0x1009:	adc	al, byte ptr [bx + si]
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x12 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	modrm_offset: 0x1
	disp: 0x0
	op_count: 2
		operands[0].type: REG = al
		operands[0].size: 1
		operands[0].access: READ | WRITE
		operands[1].type: MEM
			operands[1].mem.base: REG = bx
			operands[1].mem.index: REG = si
		operands[1].size: 1
		operands[1].access: READ
	Registers read: flags al bx si
	Registers modified: flags al
	EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

0x100b:	add	byte ptr [di], al
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x00 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x5
	modrm_offset: 0x1
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = di
		operands[0].size: 1
		operands[0].access: READ | WRITE
		operands[1].type: REG = al
		operands[1].size: 1
		operands[1].access: READ
	Registers read: di al
	Registers modified: flags
	EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

0x100d:	and	ax, word ptr [bx + di]
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x23 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x1
	modrm_offset: 0x1
	disp: 0x0
	op_count: 2
		operands[0].type: REG = ax
		operands[0].size: 2
		operands[0].access: READ | WRITE
		operands[1].type: MEM
			operands[1].mem.base: REG = bx
			operands[1].mem.index: REG = di
		operands[1].size: 2
		operands[1].access: READ
	Registers read: ax bx di
	Registers modified: flags ax
	EFLAGS: MOD_SF MOD_ZF MOD_PF RESET_OF RESET_CF UNDEF_AF

0x100f:	add	byte ptr [bx + si], al
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x00 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	modrm_offset: 0x1
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = si
		operands[0].size: 1
		operands[0].access: READ | WRITE
		operands[1].type: REG = al
		operands[1].size: 1
		operands[1].access: READ
	Registers read: bx si al
	Registers modified: flags
	EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

0x1011:	mov	ax, word ptr ss:[si + 0x2391]
	Prefix:0x00 0x36 0x00 0x00 
	Opcode:0x8b 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x84
	modrm_offset: 0x2
	disp: 0x2391
	disp_offset: 0x3
	disp_size: 0x2
	op_count: 2
		operands[0].type: REG = ax
		operands[0].size: 2
		operands[0].access: WRITE
		operands[1].type: MEM
			operands[1].mem.segment: REG = ss
			operands[1].mem.base: REG = si
			operands[1].mem.disp: 0x2391
		operands[1].size: 2
		operands[1].access: READ
	Registers read: ss si
	Registers modified: ax

0x1016:	add	word ptr [bx + si], ax
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x01 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	modrm_offset: 0x1
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = si
		operands[0].size: 2
		operands[0].access: READ | WRITE
		operands[1].type: REG = ax
		operands[1].size: 2
		operands[1].access: READ
	Registers read: bx si ax
	Registers modified: flags
	EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

0x1018:	add	byte ptr [bx + di - 0x73], al
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x00 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x41
	modrm_offset: 0x1
	disp: 0xffffffffffffff8d
	disp_offset: 0x2
	disp_size: 0x1
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = di
			operands[0].mem.disp: 0xffffffffffffff8d
		operands[0].size: 1
		operands[0].access: READ | WRITE
		operands[1].type: REG = al
		operands[1].size: 1
		operands[1].access: READ
	Registers read: bx di al
	Registers modified: flags
	EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

0x101b:	test	byte ptr [bx + di], bh
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x84 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x39
	modrm_offset: 0x1
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = di
		operands[0].size: 1
		operands[1].type: REG = bh
		operands[1].size: 1
	Registers read: bx di

0x101d:	mov	word ptr [bx], sp
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x89 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x67
	modrm_offset: 0x1
	disp: 0x0
	disp_offset: 0x2
	disp_size: 0x1
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
		operands[0].size: 2
		operands[0].access: WRITE
		operands[1].type: REG = sp
		operands[1].size: 2
		operands[1].access: READ
	Registers read: bx sp

0x1020:	add	byte ptr [di - 0x7679], cl
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x00 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x8d
	modrm_offset: 0x1
	disp: 0xffffffffffff8987
	disp_offset: 0x2
	disp_size: 0x2
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = di
			operands[0].mem.disp: 0xffffffffffff8987
		operands[0].size: 1
		operands[0].access: READ | WRITE
		operands[1].type: REG = cl
		operands[1].size: 1
		operands[1].access: READ
	Registers read: di cl
	Registers modified: flags
	EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

0x1024:	add	byte ptr [eax], al
	Prefix:0x00 0x00 0x00 0x67 
	Opcode:0x00 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	modrm_offset: 0x2
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = eax
		operands[0].size: 1
		operands[0].access: READ | WRITE
		operands[1].type: REG = al
		operands[1].size: 1
		operands[1].access: READ
	Registers read: eax al
	Registers modified: flags
	EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

0x1027:	mov	ah, 0xc6
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0xb4 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	disp: 0x0
	imm_count: 1
		imms[1]: 0xc6
	imm_offset: 0x1
	imm_size: 0x1
	op_count: 2
		operands[0].type: REG = ah
		operands[0].size: 1
		operands[0].access: WRITE
		operands[1].type: IMM = 0xc6
		operands[1].size: 1
	Registers modified: ah

0x1029:	jmp	0x10e7
	Prefix:0x00 0x00 0x66 0x00 
	Opcode:0xe9 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	disp: 0x0
	imm_count: 1
		imms[1]: 0x10e7
	imm_offset: 0x2
	imm_size: 0x4
	op_count: 1
		operands[0].type: IMM = 0x10e7
		operands[0].size: 4

0x102f:	jmp	word ptr [eax + 0x123]
	Prefix:0x00 0x00 0x00 0x67 
	Opcode:0xff 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0xa0
	modrm_offset: 0x2
	disp: 0x123
	disp_offset: 0x3
	disp_size: 0x4
	op_count: 1
		operands[0].type: MEM
			operands[0].mem.base: REG = eax
			operands[0].mem.disp: 0x123
		operands[0].size: 2
		operands[0].access: READ
	Registers read: eax

0x1036:	call	0x1107
	Prefix:0x00 0x00 0x66 0x00 
	Opcode:0xe8 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	disp: 0x0
	imm_count: 1
		imms[1]: 0x1107
	imm_offset: 0x2
	imm_size: 0x4
	op_count: 1
		operands[0].type: IMM = 0x1107
		operands[0].size: 4
	Registers read: esp eip
	Registers modified: esp

0x103c:	je	0x103a
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x74 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	disp: 0x0
	imm_count: 1
		imms[1]: 0x103a
	imm_offset: 0x1
	imm_size: 0x1
	op_count: 1
		operands[0].type: IMM = 0x103a
		operands[0].size: 2
	Registers read: flags
	EFLAGS: TEST_ZF

0x103e:

****************
Platform: X86 32 (AT&T syntax)
Code:0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00 0x05 0x23 0x01 0x00 0x00 0x36 0x8b 0x84 0x91 0x23 0x01 0x00 0x00 0x41 0x8d 0x84 0x39 0x89 0x67 0x00 0x00 0x8d 0x87 0x89 0x67 0x00 0x00 0xb4 0xc6 0xe9 0xea 0xbe 0xad 0xde 0xff 0xa0 0x23 0x01 0x00 0x00 0xe8 0xdf 0xbe 0xad 0xde 0x74 0xff 
Disasm:
0x1000:	leal	8(%edx, %esi), %ecx
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x8d 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x4c
	modrm_offset: 0x1
	disp: 0x8
	disp_offset: 0x3
	disp_size: 0x1
	sib: 0x32
		sib_base: edx
		sib_index: esi
		sib_scale: 1
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = edx
			operands[0].mem.index: REG = esi
			operands[0].mem.disp: 0x8
		operands[0].size: 4
		operands[0].access: READ
		operands[1].type: REG = ecx
		operands[1].size: 4
		operands[1].access: WRITE
	Registers read: edx esi
	Registers modified: ecx

0x1004:	addl	%ebx, %eax
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x01 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0xd8
	modrm_offset: 0x1
	disp: 0x0
	sib: 0x0
	op_count: 2
		operands[0].type: REG = ebx
		operands[0].size: 4
		operands[0].access: READ
		operands[1].type: REG = eax
		operands[1].size: 4
		operands[1].access: READ | WRITE
	Registers read: ebx eax
	Registers modified: eflags eax
	EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

0x1006:	addl	$0x1234, %esi
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x81 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0xc6
	modrm_offset: 0x1
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0x1234
	imm_offset: 0x2
	imm_size: 0x4
	op_count: 2
		operands[0].type: IMM = 0x1234
		operands[0].size: 4
		operands[1].type: REG = esi
		operands[1].size: 4
		operands[1].access: READ | WRITE
	Registers read: esi
	Registers modified: eflags esi
	EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

0x100c:	addl	$0x123, %eax
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x05 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0x123
	imm_offset: 0x1
	imm_size: 0x4
	op_count: 2
		operands[0].type: IMM = 0x123
		operands[0].size: 4
		operands[1].type: REG = eax
		operands[1].size: 4
		operands[1].access: READ | WRITE
	Registers read: eax
	Registers modified: eflags eax
	EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

0x1011:	movl	%ss:0x123(%ecx, %edx, 4), %eax
	Prefix:0x00 0x36 0x00 0x00 
	Opcode:0x8b 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x84
	modrm_offset: 0x2
	disp: 0x123
	disp_offset: 0x4
	disp_size: 0x4
	sib: 0x91
		sib_base: ecx
		sib_index: edx
		sib_scale: 4
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.segment: REG = ss
			operands[0].mem.base: REG = ecx
			operands[0].mem.index: REG = edx
			operands[0].mem.scale: 4
			operands[0].mem.disp: 0x123
		operands[0].size: 4
		operands[0].access: READ
		operands[1].type: REG = eax
		operands[1].size: 4
		operands[1].access: WRITE
	Registers read: ss ecx edx
	Registers modified: eax

0x1019:	incl	%ecx
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x41 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	op_count: 1
		operands[0].type: REG = ecx
		operands[0].size: 4
		operands[0].access: READ | WRITE
	Registers read: ecx
	Registers modified: eflags ecx
	EFLAGS: MOD_AF MOD_SF MOD_ZF MOD_PF MOD_OF

0x101a:	leal	0x6789(%ecx, %edi), %eax
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x8d 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x84
	modrm_offset: 0x1
	disp: 0x6789
	disp_offset: 0x3
	disp_size: 0x4
	sib: 0x39
		sib_base: ecx
		sib_index: edi
		sib_scale: 1
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = ecx
			operands[0].mem.index: REG = edi
			operands[0].mem.disp: 0x6789
		operands[0].size: 4
		operands[0].access: READ
		operands[1].type: REG = eax
		operands[1].size: 4
		operands[1].access: WRITE
	Registers read: ecx edi
	Registers modified: eax

0x1021:	leal	0x6789(%edi), %eax
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x8d 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x87
	modrm_offset: 0x1
	disp: 0x6789
	disp_offset: 0x2
	disp_size: 0x4
	sib: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = edi
			operands[0].mem.disp: 0x6789
		operands[0].size: 4
		operands[0].access: READ
		operands[1].type: REG = eax
		operands[1].size: 4
		operands[1].access: WRITE
	Registers read: edi
	Registers modified: eax

0x1027:	movb	$0xc6, %ah
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0xb4 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0xc6
	imm_offset: 0x1
	imm_size: 0x1
	op_count: 2
		operands[0].type: IMM = 0xc6
		operands[0].size: 1
		operands[1].type: REG = ah
		operands[1].size: 1
		operands[1].access: WRITE
	Registers modified: ah

0x1029:	jmp	0xdeadcf18
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0xe9 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0xdeadcf18
	imm_offset: 0x1
	imm_size: 0x4
	op_count: 1
		operands[0].type: IMM = 0xdeadcf18
		operands[0].size: 4

0x102e:	jmpl	*0x123(%eax)
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0xff 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0xa0
	modrm_offset: 0x1
	disp: 0x123
	disp_offset: 0x2
	disp_size: 0x4
	sib: 0x0
	op_count: 1
		operands[0].type: MEM
			operands[0].mem.base: REG = eax
			operands[0].mem.disp: 0x123
		operands[0].size: 4
		operands[0].access: READ
	Registers read: eax

0x1034:	calll	0xdeadcf18
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0xe8 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0xdeadcf18
	imm_offset: 0x1
	imm_size: 0x4
	op_count: 1
		operands[0].type: IMM = 0xdeadcf18
		operands[0].size: 4
	Registers read: esp eip
	Registers modified: esp

0x1039:	je	0x103a
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x74 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0x103a
	imm_offset: 0x1
	imm_size: 0x1
	op_count: 1
		operands[0].type: IMM = 0x103a
		operands[0].size: 4
	Registers read: eflags
	EFLAGS: TEST_ZF

0x103b:

****************
Platform: X86 32 (Intel syntax)
Code:0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00 0x05 0x23 0x01 0x00 0x00 0x36 0x8b 0x84 0x91 0x23 0x01 0x00 0x00 0x41 0x8d 0x84 0x39 0x89 0x67 0x00 0x00 0x8d 0x87 0x89 0x67 0x00 0x00 0xb4 0xc6 0xe9 0xea 0xbe 0xad 0xde 0xff 0xa0 0x23 0x01 0x00 0x00 0xe8 0xdf 0xbe 0xad 0xde 0x74 0xff 
Disasm:
0x1000:	lea	ecx, [edx + esi + 8]
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x8d 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x4c
	modrm_offset: 0x1
	disp: 0x8
	disp_offset: 0x3
	disp_size: 0x1
	sib: 0x32
		sib_base: edx
		sib_index: esi
		sib_scale: 1
	op_count: 2
		operands[0].type: REG = ecx
		operands[0].size: 4
		operands[0].access: WRITE
		operands[1].type: MEM
			operands[1].mem.base: REG = edx
			operands[1].mem.index: REG = esi
			operands[1].mem.disp: 0x8
		operands[1].size: 4
		operands[1].access: READ
	Registers read: edx esi
	Registers modified: ecx

0x1004:	add	eax, ebx
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x01 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0xd8
	modrm_offset: 0x1
	disp: 0x0
	sib: 0x0
	op_count: 2
		operands[0].type: REG = eax
		operands[0].size: 4
		operands[0].access: READ | WRITE
		operands[1].type: REG = ebx
		operands[1].size: 4
		operands[1].access: READ
	Registers read: eax ebx
	Registers modified: eflags eax
	EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

0x1006:	add	esi, 0x1234
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x81 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0xc6
	modrm_offset: 0x1
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0x1234
	imm_offset: 0x2
	imm_size: 0x4
	op_count: 2
		operands[0].type: REG = esi
		operands[0].size: 4
		operands[0].access: READ | WRITE
		operands[1].type: IMM = 0x1234
		operands[1].size: 4
	Registers read: esi
	Registers modified: eflags esi
	EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

0x100c:	add	eax, 0x123
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x05 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0x123
	imm_offset: 0x1
	imm_size: 0x4
	op_count: 2
		operands[0].type: REG = eax
		operands[0].size: 4
		operands[0].access: READ | WRITE
		operands[1].type: IMM = 0x123
		operands[1].size: 4
	Registers read: eax
	Registers modified: eflags eax
	EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

0x1011:	mov	eax, dword ptr ss:[ecx + edx*4 + 0x123]
	Prefix:0x00 0x36 0x00 0x00 
	Opcode:0x8b 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x84
	modrm_offset: 0x2
	disp: 0x123
	disp_offset: 0x4
	disp_size: 0x4
	sib: 0x91
		sib_base: ecx
		sib_index: edx
		sib_scale: 4
	op_count: 2
		operands[0].type: REG = eax
		operands[0].size: 4
		operands[0].access: WRITE
		operands[1].type: MEM
			operands[1].mem.segment: REG = ss
			operands[1].mem.base: REG = ecx
			operands[1].mem.index: REG = edx
			operands[1].mem.scale: 4
			operands[1].mem.disp: 0x123
		operands[1].size: 4
		operands[1].access: READ
	Registers read: ss ecx edx
	Registers modified: eax

0x1019:	inc	ecx
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x41 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	op_count: 1
		operands[0].type: REG = ecx
		operands[0].size: 4
		operands[0].access: READ | WRITE
	Registers read: ecx
	Registers modified: eflags ecx
	EFLAGS: MOD_AF MOD_SF MOD_ZF MOD_PF MOD_OF

0x101a:	lea	eax, [ecx + edi + 0x6789]
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x8d 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x84
	modrm_offset: 0x1
	disp: 0x6789
	disp_offset: 0x3
	disp_size: 0x4
	sib: 0x39
		sib_base: ecx
		sib_index: edi
		sib_scale: 1
	op_count: 2
		operands[0].type: REG = eax
		operands[0].size: 4
		operands[0].access: WRITE
		operands[1].type: MEM
			operands[1].mem.base: REG = ecx
			operands[1].mem.index: REG = edi
			operands[1].mem.disp: 0x6789
		operands[1].size: 4
		operands[1].access: READ
	Registers read: ecx edi
	Registers modified: eax

0x1021:	lea	eax, [edi + 0x6789]
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x8d 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x87
	modrm_offset: 0x1
	disp: 0x6789
	disp_offset: 0x2
	disp_size: 0x4
	sib: 0x0
	op_count: 2
		operands[0].type: REG = eax
		operands[0].size: 4
		operands[0].access: WRITE
		operands[1].type: MEM
			operands[1].mem.base: REG = edi
			operands[1].mem.disp: 0x6789
		operands[1].size: 4
		operands[1].access: READ
	Registers read: edi
	Registers modified: eax

0x1027:	mov	ah, 0xc6
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0xb4 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0xc6
	imm_offset: 0x1
	imm_size: 0x1
	op_count: 2
		operands[0].type: REG = ah
		operands[0].size: 1
		operands[0].access: WRITE
		operands[1].type: IMM = 0xc6
		operands[1].size: 1
	Registers modified: ah

0x1029:	jmp	0xdeadcf18
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0xe9 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0xdeadcf18
	imm_offset: 0x1
	imm_size: 0x4
	op_count: 1
		operands[0].type: IMM = 0xdeadcf18
		operands[0].size: 4

0x102e:	jmp	dword ptr [eax + 0x123]
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0xff 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0xa0
	modrm_offset: 0x1
	disp: 0x123
	disp_offset: 0x2
	disp_size: 0x4
	sib: 0x0
	op_count: 1
		operands[0].type: MEM
			operands[0].mem.base: REG = eax
			operands[0].mem.disp: 0x123
		operands[0].size: 4
		operands[0].access: READ
	Registers read: eax

0x1034:	call	0xdeadcf18
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0xe8 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0xdeadcf18
	imm_offset: 0x1
	imm_size: 0x4
	op_count: 1
		operands[0].type: IMM = 0xdeadcf18
		operands[0].size: 4
	Registers read: esp eip
	Registers modified: esp

0x1039:	je	0x103a
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x74 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0x103a
	imm_offset: 0x1
	imm_size: 0x1
	op_count: 1
		operands[0].type: IMM = 0x103a
		operands[0].size: 4
	Registers read: eflags
	EFLAGS: TEST_ZF

0x103b:

****************
Platform: X86 64 (Intel syntax)
Code:0x55 0x48 0x8b 0x05 0xb8 0x13 0x00 0x00 0xe9 0xea 0xbe 0xad 0xde 0xff 0x25 0x23 0x01 0x00 0x00 0xe8 0xdf 0xbe 0xad 0xde 0x74 0xff 
Disasm:
0x1000:	push	rbp
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x55 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 8
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	op_count: 1
		operands[0].type: REG = rbp
		operands[0].size: 8
		operands[0].access: READ
	Registers read: rsp rbp
	Registers modified: rsp

0x1001:	mov	rax, qword ptr [rip + 0x13b8]
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x8b 0x00 0x00 0x00 
	rex: 0x48
	addr_size: 8
	modrm: 0x5
	modrm_offset: 0x2
	disp: 0x13b8
	disp_offset: 0x3
	disp_size: 0x4
	sib: 0x0
	op_count: 2
		operands[0].type: REG = rax
		operands[0].size: 8
		operands[0].access: WRITE
		operands[1].type: MEM
			operands[1].mem.base: REG = rip
			operands[1].mem.disp: 0x13b8
		operands[1].size: 8
		operands[1].access: READ
	Registers read: rip
	Registers modified: rax

0x1008:	jmp	0xffffffffdeadcef7
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0xe9 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 8
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0xffffffffdeadcef7
	imm_offset: 0x1
	imm_size: 0x4
	op_count: 1
		operands[0].type: IMM = 0xffffffffdeadcef7
		operands[0].size: 8

0x100d:	jmp	qword ptr [rip + 0x123]
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0xff 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 8
	modrm: 0x25
	modrm_offset: 0x1
	disp: 0x123
	disp_offset: 0x2
	disp_size: 0x4
	sib: 0x0
	op_count: 1
		operands[0].type: MEM
			operands[0].mem.base: REG = rip
			operands[0].mem.disp: 0x123
		operands[0].size: 8
		operands[0].access: READ
	Registers read: rip

0x1013:	call	0xffffffffdeadcef7
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0xe8 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 8
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0xffffffffdeadcef7
	imm_offset: 0x1
	imm_size: 0x4
	op_count: 1
		operands[0].type: IMM = 0xffffffffdeadcef7
		operands[0].size: 8
	Registers read: rsp rip
	Registers modified: rsp

0x1018:	je	0x1019
	Prefix:0x00 0x00 0x00 0x00 
	Opcode:0x74 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 8
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0x1019
	imm_offset: 0x1
	imm_size: 0x1
	op_count: 1
		operands[0].type: IMM = 0x1019
		operands[0].size: 8
	Registers read: rflags
	EFLAGS: TEST_ZF

0x101a:

