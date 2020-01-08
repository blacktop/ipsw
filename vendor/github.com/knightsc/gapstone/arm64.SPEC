****************
Platform: ARM-64
Code: 0x09 0x00 0x38 0xd5 0xbf 0x40 0x00 0xd5 0x0c 0x05 0x13 0xd5 0x20 0x50 0x02 0x0e 0x20 0xe4 0x3d 0x0f 0x00 0x18 0xa0 0x5f 0xa2 0x00 0xae 0x9e 0x9f 0x37 0x03 0xd5 0xbf 0x33 0x03 0xd5 0xdf 0x3f 0x03 0xd5 0x21 0x7c 0x02 0x9b 0x21 0x7c 0x00 0x53 0x00 0x40 0x21 0x4b 0xe1 0x0b 0x40 0xb9 0x20 0x04 0x81 0xda 0x20 0x08 0x02 0x8b 0x10 0x5b 0xe8 0x3c 
Disasm:
0x2c:	mrs	x9, midr_el1
	op_count: 2
		operands[0].type: REG = x9
		operands[0].access: READ | WRITE
		operands[1].type: SYS = 0xc000
		operands[1].access: READ | WRITE
	Registers read: x9
	Registers modified: x9

0x30:	msr	spsel, #0
	op_count: 2
		operands[0].type: PSTATE = 0x5
		operands[0].access: READ | WRITE
		operands[1].type: IMM = 0x0
		operands[1].access: READ
	Update-flags: True
	Registers modified: nzcv

0x34:	msr	dbgdtrtx_el0, x12
	op_count: 2
		operands[0].type: SYS = 0x9828
		operands[0].access: READ | WRITE
		operands[1].type: REG = x12
		operands[1].access: READ | WRITE
	Registers read: x12
	Registers modified: x12

0x38:	tbx	v0.8b, {v1.16b, v2.16b, v3.16b}, v2.8b
	op_count: 5
		operands[0].type: REG = v0
		operands[0].access: READ | WRITE
			Vector Arrangement Specifier: 0x2
		operands[1].type: REG = v1
		operands[1].access: READ
			Vector Arrangement Specifier: 0x1
		operands[2].type: REG = v2
		operands[2].access: READ
			Vector Arrangement Specifier: 0x1
		operands[3].type: REG = v3
		operands[3].access: READ
			Vector Arrangement Specifier: 0x1
		operands[4].type: REG = v2
			Vector Arrangement Specifier: 0x2
	Registers read: v0 v1 v2 v3
	Registers modified: v0

0x3c:	scvtf	v0.2s, v1.2s, #3
	op_count: 3
		operands[0].type: REG = v0
		operands[0].access: WRITE
			Vector Arrangement Specifier: 0xa
		operands[1].type: REG = v1
		operands[1].access: READ
			Vector Arrangement Specifier: 0xa
		operands[2].type: IMM = 0x3
		operands[2].access: READ
	Registers read: v1
	Registers modified: v0

0x40:	fmla	s0, s0, v0.s[3]
	op_count: 3
		operands[0].type: REG = s0
		operands[0].access: READ | WRITE
		operands[1].type: REG = s0
		operands[1].access: READ
		operands[2].type: REG = v0
		operands[2].access: READ
			Vector Arrangement Specifier: 0xb
			Vector Index: 3
	Registers read: s0 v0
	Registers modified: s0

0x44:	fmov	x2, v5.d[1]
	op_count: 2
		operands[0].type: REG = x2
		operands[0].access: WRITE
		operands[1].type: REG = v5
		operands[1].access: READ
			Vector Index: 1
	Registers read: v5
	Registers modified: x2

0x48:	dsb	nsh
	op_count: 1
		operands[0].type: BARRIER = 0x7
		operands[0].access: READ

0x4c:	dmb	osh
	op_count: 1
		operands[0].type: BARRIER = 0x3
		operands[0].access: READ

0x50:	isb	

0x54:	mul	x1, x1, x2
	op_count: 3
		operands[0].type: REG = x1
		operands[0].access: WRITE
		operands[1].type: REG = x1
		operands[1].access: READ
		operands[2].type: REG = x2
		operands[2].access: READ
	Registers read: x1 x2
	Registers modified: x1

0x58:	lsr	w1, w1, #0
	op_count: 3
		operands[0].type: REG = w1
		operands[0].access: READ | WRITE
		operands[1].type: REG = w1
		operands[1].access: READ
		operands[2].type: IMM = 0x0
		operands[2].access: READ
	Registers read: w1
	Registers modified: w1

0x5c:	sub	w0, w0, w1, uxtw
	op_count: 3
		operands[0].type: REG = w0
		operands[0].access: WRITE
		operands[1].type: REG = w0
		operands[1].access: READ
		operands[2].type: REG = w1
		operands[2].access: READ
			Ext: 3
	Registers read: w0 w1
	Registers modified: w0

0x60:	ldr	w1, [sp, #8]
	op_count: 2
		operands[0].type: REG = w1
		operands[0].access: WRITE
		operands[1].type: MEM
			operands[1].mem.base: REG = sp
			operands[1].mem.disp: 0x8
		operands[1].access: READ
	Registers read: sp
	Registers modified: w1

0x64:	cneg	x0, x1, ne
	op_count: 2
		operands[0].type: REG = x0
		operands[0].access: WRITE
		operands[1].type: REG = x1
		operands[1].access: READ
	Code-condition: 2
	Registers read: nzcv x1
	Registers modified: x0

0x68:	add	x0, x1, x2, lsl #2
	op_count: 3
		operands[0].type: REG = x0
		operands[0].access: WRITE
		operands[1].type: REG = x1
		operands[1].access: READ
		operands[2].type: REG = x2
		operands[2].access: READ
			Shift: type = 1, value = 2
	Registers read: x1 x2
	Registers modified: x0

0x6c:	ldr	q16, [x24, w8, uxtw #4]
	op_count: 2
		operands[0].type: REG = q16
		operands[0].access: WRITE
		operands[1].type: MEM
			operands[1].mem.base: REG = x24
			operands[1].mem.index: REG = w8
		operands[1].access: READ
			Shift: type = 1, value = 4
			Ext: 3
	Registers read: x24 w8
	Registers modified: q16

0x70:

