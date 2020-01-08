****************
Platform: ARM
Code:0x86 0x48 0x60 0xf4 0x4d 0x0f 0xe2 0xf4 0xed 0xff 0xff 0xeb 0x04 0xe0 0x2d 0xe5 0x00 0x00 0x00 0x00 0xe0 0x83 0x22 0xe5 0xf1 0x02 0x03 0x0e 0x00 0x00 0xa0 0xe3 0x02 0x30 0xc1 0xe7 0x00 0x00 0x53 0xe3 0x00 0x02 0x01 0xf1 0x05 0x40 0xd0 0xe8 0xf4 0x80 0x00 0x00 
Disasm:
0x80001000:	vld2.32	{d20, d21}, [r0], r6
	op_count: 4
		operands[0].type: REG = d20
		operands[0].access: WRITE
		operands[1].type: REG = d21
		operands[1].access: WRITE
		operands[2].type: MEM
			operands[2].mem.base: REG = r0
		operands[2].access: READ
		operands[3].type: REG = r6
		operands[3].access: READ
	Vector-size: 32
	Registers read: r0 r6
	Registers modified: d20 d21

0x80001004:	vld4.16	{d16[], d17[], d18[], d19[]}, [r2]!
	op_count: 5
		operands[0].type: REG = d16
		operands[0].access: WRITE
		operands[1].type: REG = d17
		operands[1].access: WRITE
		operands[2].type: REG = d18
		operands[2].access: WRITE
		operands[3].type: REG = d19
		operands[3].access: WRITE
		operands[4].type: MEM
			operands[4].mem.base: REG = r2
		operands[4].access: READ
	Write-back: True
	Vector-size: 16
	Registers read: r2
	Registers modified: d16 d17 d18 d19 r2

0x80001008:	bl	#0x80000fc4
	op_count: 1
		operands[0].type: IMM = 0x80000fc4
	Registers read: pc
	Registers modified: lr pc

0x8000100c:	str	lr, [sp, #-4]!
	op_count: 2
		operands[0].type: REG = lr
		operands[0].access: READ
		operands[1].type: MEM
			operands[1].mem.base: REG = sp
			operands[1].mem.disp: 0xfffffffc
		operands[1].access: WRITE
	Write-back: True
	Registers read: lr sp
	Registers modified: sp

0x80001010:	andeq	r0, r0, r0
	op_count: 3
		operands[0].type: REG = r0
		operands[0].access: WRITE
		operands[1].type: REG = r0
		operands[1].access: READ
		operands[2].type: REG = r0
		operands[2].access: READ
	Code condition: 1
	Registers read: r0
	Registers modified: r0

0x80001014:	str	r8, [r2, #-0x3e0]!
	op_count: 2
		operands[0].type: REG = r8
		operands[0].access: READ
		operands[1].type: MEM
			operands[1].mem.base: REG = r2
			operands[1].mem.disp: 0xfffffc20
		operands[1].access: WRITE
	Write-back: True
	Registers read: r8 r2
	Registers modified: r2

0x80001018:	mcreq	p2, #0, r0, c3, c1, #7
	op_count: 6
		operands[0].type: P-IMM = 2
		operands[1].type: IMM = 0x0
		operands[2].type: REG = r0
		operands[2].access: READ
		operands[3].type: C-IMM = 3
		operands[4].type: C-IMM = 1
		operands[5].type: IMM = 0x7
	Code condition: 1
	Registers read: r0

0x8000101c:	mov	r0, #0
	op_count: 2
		operands[0].type: REG = r0
		operands[0].access: WRITE
		operands[1].type: IMM = 0x0
	Registers modified: r0

0x80001020:	strb	r3, [r1, r2]
	op_count: 2
		operands[0].type: REG = r3
		operands[0].access: READ
		operands[1].type: MEM
			operands[1].mem.base: REG = r1
			operands[1].mem.index: REG = r2
		operands[1].access: WRITE
	Registers read: r3 r1 r2

0x80001024:	cmp	r3, #0
	op_count: 2
		operands[0].type: REG = r3
		operands[0].access: READ
		operands[1].type: IMM = 0x0
	Update-flags: True
	Registers read: r3
	Registers modified: cpsr

0x80001028:	setend	be
	op_count: 1
		operands[0].type: SETEND = be

0x8000102c:	ldm	r0, {r0, r2, lr} ^
	op_count: 4
		operands[0].type: REG = r0
		operands[0].access: READ
		operands[1].type: REG = r0
		operands[1].access: WRITE
		operands[2].type: REG = r2
		operands[2].access: WRITE
		operands[3].type: REG = lr
		operands[3].access: WRITE
	User-mode: True
	Registers read: r0
	Registers modified: r0 r2 lr

0x80001030:	strdeq	r8, sb, [r0], -r4
	op_count: 4
		operands[0].type: REG = r8
		operands[0].access: READ
		operands[1].type: REG = sb
		operands[1].access: READ
		operands[2].type: MEM
			operands[2].mem.base: REG = r0
		operands[2].access: READ
		operands[3].type: REG = r4
		operands[3].access: READ
		Subtracted: True
	Code condition: 1
	Write-back: True
	Registers read: r8 sb r0 r4
	Registers modified: r0

0x80001034:

****************
Platform: Thumb
Code:0x60 0xf9 0x1f 0x04 0xe0 0xf9 0x4f 0x07 0x70 0x47 0x00 0xf0 0x10 0xe8 0xeb 0x46 0x83 0xb0 0xc9 0x68 0x1f 0xb1 0x30 0xbf 0xaf 0xf3 0x20 0x84 0x52 0xf8 0x23 0xf0 
Disasm:
0x80001000:	vld3.8	{d16, d17, d18}, [r0:0x40]
	op_count: 4
		operands[0].type: REG = d16
		operands[0].access: WRITE
		operands[1].type: REG = d17
		operands[1].access: WRITE
		operands[2].type: REG = d18
		operands[2].access: WRITE
		operands[3].type: MEM
			operands[3].mem.base: REG = r0
			operands[3].mem.disp: 0x40
		operands[3].access: READ
	Vector-size: 8
	Registers read: r0
	Registers modified: d16 d17 d18

0x80001004:	vld4.16	{d16[1], d17[1], d18[1], d19[1]}, [r0]
	op_count: 5
		operands[0].type: REG = d16
		operands[0].neon_lane = 1
		operands[0].access: WRITE
		operands[1].type: REG = d17
		operands[1].neon_lane = 1
		operands[1].access: WRITE
		operands[2].type: REG = d18
		operands[2].neon_lane = 1
		operands[2].access: WRITE
		operands[3].type: REG = d19
		operands[3].neon_lane = 1
		operands[3].access: WRITE
		operands[4].type: MEM
			operands[4].mem.base: REG = r0
		operands[4].access: READ
	Vector-size: 16
	Registers read: r0
	Registers modified: d16 d17 d18 d19

0x80001008:	bx	lr
	op_count: 1
		operands[0].type: REG = lr
		operands[0].access: READ
	Registers read: lr
	Registers modified: pc

0x8000100a:	blx	#0x8000102c
	op_count: 1
		operands[0].type: IMM = 0x8000102c
	Registers read: pc
	Registers modified: lr pc

0x8000100e:	mov	fp, sp
	op_count: 2
		operands[0].type: REG = fp
		operands[0].access: WRITE
		operands[1].type: REG = sp
		operands[1].access: READ
	Registers read: sp
	Registers modified: fp

0x80001010:	sub	sp, #0xc
	op_count: 2
		operands[0].type: REG = sp
		operands[0].access: READ | WRITE
		operands[1].type: IMM = 0xc
	Registers read: sp
	Registers modified: sp

0x80001012:	ldr	r1, [r1, #0xc]
	op_count: 2
		operands[0].type: REG = r1
		operands[0].access: WRITE
		operands[1].type: MEM
			operands[1].mem.base: REG = r1
			operands[1].mem.disp: 0xc
		operands[1].access: READ
	Registers read: r1
	Registers modified: r1

0x80001014:	cbz	r7, #0x8000101e
	op_count: 2
		operands[0].type: REG = r7
		operands[0].access: READ
		operands[1].type: IMM = 0x8000101e
	Registers read: r7

0x80001016:	wfi	

0x80001018:	cpsie.w	f
	CPSI-mode: 2
	CPSI-flag: 1

0x8000101c:	ldr.w	pc, [r2, r3, lsl #2]
	op_count: 2
		operands[0].type: REG = pc
		operands[0].access: WRITE
		operands[1].type: MEM
			operands[1].mem.base: REG = r2
			operands[1].mem.index: REG = r3
		operands[1].access: READ
			Shift: 2 = 2
	Registers read: r2 r3
	Registers modified: pc

0x80001020:

****************
Platform: Thumb-mixed
Code:0xd1 0xe8 0x00 0xf0 0xf0 0x24 0x04 0x07 0x1f 0x3c 0xf2 0xc0 0x00 0x00 0x4f 0xf0 0x00 0x01 0x46 0x6c 
Disasm:
0x80001000:	tbb	[r1, r0]
	op_count: 1
		operands[0].type: MEM
			operands[0].mem.base: REG = r1
			operands[0].mem.index: REG = r0
		operands[0].access: READ
	Registers read: r1 r0

0x80001004:	movs	r4, #0xf0
	op_count: 2
		operands[0].type: REG = r4
		operands[0].access: WRITE
		operands[1].type: IMM = 0xf0
	Update-flags: True
	Registers modified: r4

0x80001006:	lsls	r4, r0, #0x1c
	op_count: 3
		operands[0].type: REG = r4
		operands[0].access: WRITE
		operands[1].type: REG = r0
		operands[1].access: READ
		operands[2].type: IMM = 0x1c
	Update-flags: True
	Registers read: r0
	Registers modified: r4

0x80001008:	subs	r4, #0x1f
	op_count: 2
		operands[0].type: REG = r4
		operands[0].access: READ | WRITE
		operands[1].type: IMM = 0x1f
	Update-flags: True
	Registers read: r4
	Registers modified: r4

0x8000100a:	stm	r0!, {r1, r4, r5, r6, r7}
	op_count: 6
		operands[0].type: REG = r0
		operands[0].access: READ | WRITE
		operands[1].type: REG = r1
		operands[1].access: READ
		operands[2].type: REG = r4
		operands[2].access: READ
		operands[3].type: REG = r5
		operands[3].access: READ
		operands[4].type: REG = r6
		operands[4].access: READ
		operands[5].type: REG = r7
		operands[5].access: READ
	Write-back: True
	Registers read: r0 r1 r4 r5 r6 r7
	Registers modified: r0

0x8000100c:	movs	r0, r0
	op_count: 2
		operands[0].type: REG = r0
		operands[0].access: WRITE
		operands[1].type: REG = r0
		operands[1].access: READ
	Update-flags: True
	Registers read: r0
	Registers modified: cpsr r0

0x8000100e:	mov.w	r1, #0
	op_count: 2
		operands[0].type: REG = r1
		operands[0].access: WRITE
		operands[1].type: IMM = 0x0
	Registers modified: r1

0x80001012:	ldr	r6, [r0, #0x44]
	op_count: 2
		operands[0].type: REG = r6
		operands[0].access: WRITE
		operands[1].type: MEM
			operands[1].mem.base: REG = r0
			operands[1].mem.disp: 0x44
		operands[1].access: READ
	Registers read: r0
	Registers modified: r6

0x80001014:

****************
Platform: Thumb-2 & register named with numbers
Code:0x4f 0xf0 0x00 0x01 0xbd 0xe8 0x00 0x88 0xd1 0xe8 0x00 0xf0 0x18 0xbf 0xad 0xbf 0xf3 0xff 0x0b 0x0c 0x86 0xf3 0x00 0x89 0x80 0xf3 0x00 0x8c 0x4f 0xfa 0x99 0xf6 0xd0 0xff 0xa2 0x01 
Disasm:
0x80001000:	mov.w	r1, #0
	op_count: 2
		operands[0].type: REG = r1
		operands[0].access: WRITE
		operands[1].type: IMM = 0x0
	Registers modified: r1

0x80001004:	pop.w	{r11, pc}
	op_count: 2
		operands[0].type: REG = r11
		operands[0].access: WRITE
		operands[1].type: REG = pc
		operands[1].access: WRITE
	Registers read: sp
	Registers modified: sp r11 pc

0x80001008:	tbb	[r1, r0]
	op_count: 1
		operands[0].type: MEM
			operands[0].mem.base: REG = r1
			operands[0].mem.index: REG = r0
		operands[0].access: READ
	Registers read: r1 r0

0x8000100c:	it	ne
	Code condition: 2
	Registers modified: itstate

0x8000100e:	iteet	ge
	Code condition: 11
	Registers modified: itstate

0x80001010:	vdupne.8	d16, d11[1]
	op_count: 2
		operands[0].type: REG = d16
		operands[0].access: WRITE
		operands[1].type: REG = d11
		operands[1].access: READ
		operands[1].vector_index = 1
	Code condition: 2
	Vector-size: 8
	Registers read: d11
	Registers modified: d16

0x80001014:	msr	cpsr_fc, r6
	op_count: 2
		operands[0].type: SYSREG = 9
		operands[1].type: REG = r6
		operands[1].access: READ
	Registers read: r6

0x80001018:	msr	apsr_nzcvqg, r0
	op_count: 2
		operands[0].type: SYSREG = 259
		operands[1].type: REG = r0
		operands[1].access: READ
	Registers read: r0

0x8000101c:	sxtb.w	r6, r9, ror #8
	op_count: 2
		operands[0].type: REG = r6
		operands[0].access: WRITE
		operands[1].type: REG = r9
		operands[1].access: READ
			Shift: 4 = 8
	Registers read: r9
	Registers modified: r6

0x80001020:	vaddw.u16	q8, q8, d18
	op_count: 3
		operands[0].type: REG = q8
		operands[0].access: WRITE
		operands[1].type: REG = q8
		operands[1].access: READ
		operands[2].type: REG = d18
		operands[2].access: READ
	Vector-data: 10
	Registers read: q8 d18
	Registers modified: q8

0x80001024:

****************
Platform: Thumb-MClass
Code:0xef 0xf3 0x02 0x80 
Disasm:
0x80001000:	mrs	r0, eapsr
	op_count: 2
		operands[0].type: REG = r0
		operands[0].access: WRITE
		operands[1].type: SYSREG = 264
	Registers modified: r0

0x80001004:

****************
Platform: Arm-V8
Code:0xe0 0x3b 0xb2 0xee 0x42 0x00 0x01 0xe1 0x51 0xf0 0x7f 0xf5 
Disasm:
0x80001000:	vcvtt.f64.f16	d3, s1
	op_count: 2
		operands[0].type: REG = d3
		operands[0].access: WRITE
		operands[1].type: REG = s1
		operands[1].access: READ
	Vector-data: 18
	Registers read: s1
	Registers modified: d3

0x80001004:	crc32b	r0, r1, r2
	op_count: 3
		operands[0].type: REG = r0
		operands[0].access: WRITE
		operands[1].type: REG = r1
		operands[1].access: READ
		operands[2].type: REG = r2
		operands[2].access: READ
	Registers read: r1 r2
	Registers modified: r0

0x80001008:	dmb	oshld
	Memory-barrier: 2

0x8000100c:

