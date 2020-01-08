****************
Platform: riscv32
Code:0x37 0x34 0x00 0x00 0x97 0x82 0x00 0x00 0xef 0x00 0x80 0x00 0xef 0xf0 0x1f 0xff 0xe7 0x00 0x45 0x00 0xe7 0x00 0xc0 0xff 0x63 0x05 0x41 0x00 0xe3 0x9d 0x61 0xfe 0x63 0xca 0x93 0x00 0x63 0x53 0xb5 0x00 0x63 0x65 0xd6 0x00 0x63 0x76 0xf7 0x00 0x03 0x88 0x18 0x00 0x03 0x99 0x49 0x00 0x03 0xaa 0x6a 0x00 0x03 0xcb 0x2b 0x01 0x03 0xdc 0x8c 0x01 0x23 0x86 0xad 0x03 0x23 0x9a 0xce 0x03 0x23 0x8f 0xef 0x01 0x93 0x00 0xe0 0x00 0x13 0xa1 0x01 0x01 0x13 0xb2 0x02 0x7d 0x13 0xc3 0x03 0xdd 0x13 0xe4 0xc4 0x12 0x13 0xf5 0x85 0x0c 0x13 0x96 0xe6 0x01 0x13 0xd7 0x97 0x01 0x13 0xd8 0xf8 0x40 0x33 0x89 0x49 0x01 0xb3 0x0a 0x7b 0x41 0x33 0xac 0xac 0x01 0xb3 0x3d 0xde 0x01 0x33 0xd2 0x62 0x40 0xb3 0x43 0x94 0x00 0x33 0xe5 0xc5 0x00 0xb3 0x76 0xf7 0x00 0xb3 0x54 0x39 0x01 0xb3 0x50 0x31 0x00 0x33 0x9f 0x0f 0x00 
Disasm:
0x1000:	lui	s0, 3
	op_count: 2
		operands[0].type: REG = s0
		operands[1].type: IMM = 0x3

0x1004:	auipc	t0, 8
	op_count: 2
		operands[0].type: REG = t0
		operands[1].type: IMM = 0x8

0x1008:	jal	8
	op_count: 1
		operands[0].type: IMM = 0x8

0x100c:	jal	-0x10
	op_count: 1
		operands[0].type: IMM = 0xfffffffffffffff0

0x1010:	jalr	ra, a0, 4
	op_count: 3
		operands[0].type: REG = ra
		operands[1].type: REG = a0
		operands[2].type: IMM = 0x4

0x1014:	jalr	ra, zero, -4
	op_count: 3
		operands[0].type: REG = ra
		operands[1].type: REG = zero
		operands[2].type: IMM = 0xfffffffffffffffc

0x1018:	beq	sp, tp, 0xa
	op_count: 3
		operands[0].type: REG = sp
		operands[1].type: REG = tp
		operands[2].type: IMM = 0xa
	This instruction belongs to groups: jump 

0x101c:	bne	gp, t1, -6
	op_count: 3
		operands[0].type: REG = gp
		operands[1].type: REG = t1
		operands[2].type: IMM = 0xfffffffffffffffa
	This instruction belongs to groups: jump 

0x1020:	blt	t2, s1, 0x14
	op_count: 3
		operands[0].type: REG = t2
		operands[1].type: REG = s1
		operands[2].type: IMM = 0x14
	This instruction belongs to groups: jump 

0x1024:	bge	a0, a1, 6
	op_count: 3
		operands[0].type: REG = a0
		operands[1].type: REG = a1
		operands[2].type: IMM = 0x6
	This instruction belongs to groups: jump 

0x1028:	bltu	a2, a3, 0xa
	op_count: 3
		operands[0].type: REG = a2
		operands[1].type: REG = a3
		operands[2].type: IMM = 0xa
	This instruction belongs to groups: jump 

0x102c:	bgeu	a4, a5, 0xc
	op_count: 3
		operands[0].type: REG = a4
		operands[1].type: REG = a5
		operands[2].type: IMM = 0xc
	This instruction belongs to groups: jump 

0x1030:	lb	a6, 1(a7)
	op_count: 2
		operands[0].type: REG = a6
		operands[1].type: MEM
			operands[1].mem.base: REG = a7
			operands[1].mem.disp: 0x1

0x1034:	lh	s2, 4(s3)
	op_count: 2
		operands[0].type: REG = s2
		operands[1].type: MEM
			operands[1].mem.base: REG = s3
			operands[1].mem.disp: 0x4

0x1038:	lw	s4, 6(s5)
	op_count: 2
		operands[0].type: REG = s4
		operands[1].type: MEM
			operands[1].mem.base: REG = s5
			operands[1].mem.disp: 0x6

0x103c:	lbu	s6, 0x12(s7)
	op_count: 2
		operands[0].type: REG = s6
		operands[1].type: MEM
			operands[1].mem.base: REG = s7
			operands[1].mem.disp: 0x12

0x1040:	lhu	s8, 0x18(s9)
	op_count: 2
		operands[0].type: REG = s8
		operands[1].type: MEM
			operands[1].mem.base: REG = s9
			operands[1].mem.disp: 0x18

0x1044:	sb	s10, 0x2c(s11)
	op_count: 2
		operands[0].type: REG = s10
		operands[1].type: MEM
			operands[1].mem.base: REG = s11
			operands[1].mem.disp: 0x2c

0x1048:	sh	t3, 0x34(t4)
	op_count: 2
		operands[0].type: REG = t3
		operands[1].type: MEM
			operands[1].mem.base: REG = t4
			operands[1].mem.disp: 0x34

0x104c:	sb	t5, 0x1e(t6)
	op_count: 2
		operands[0].type: REG = t5
		operands[1].type: MEM
			operands[1].mem.base: REG = t6
			operands[1].mem.disp: 0x1e

0x1050:	addi	ra, zero, 0xe
	op_count: 3
		operands[0].type: REG = ra
		operands[1].type: REG = zero
		operands[2].type: IMM = 0xe

0x1054:	slti	sp, gp, 0x10
	op_count: 3
		operands[0].type: REG = sp
		operands[1].type: REG = gp
		operands[2].type: IMM = 0x10

0x1058:	sltiu	tp, t0, 0x7d0
	op_count: 3
		operands[0].type: REG = tp
		operands[1].type: REG = t0
		operands[2].type: IMM = 0x7d0

0x105c:	xori	t1, t2, -0x230
	op_count: 3
		operands[0].type: REG = t1
		operands[1].type: REG = t2
		operands[2].type: IMM = 0xfffffffffffffdd0

0x1060:	ori	s0, s1, 0x12c
	op_count: 3
		operands[0].type: REG = s0
		operands[1].type: REG = s1
		operands[2].type: IMM = 0x12c

0x1064:	andi	a0, a1, 0xc8
	op_count: 3
		operands[0].type: REG = a0
		operands[1].type: REG = a1
		operands[2].type: IMM = 0xc8

0x1068:	slli	a2, a3, 0x1e
	op_count: 3
		operands[0].type: REG = a2
		operands[1].type: REG = a3
		operands[2].type: IMM = 0x1e

0x106c:	srli	a4, a5, 0x19
	op_count: 3
		operands[0].type: REG = a4
		operands[1].type: REG = a5
		operands[2].type: IMM = 0x19

0x1070:	srai	a6, a7, 0xf
	op_count: 3
		operands[0].type: REG = a6
		operands[1].type: REG = a7
		operands[2].type: IMM = 0xf

0x1074:	add	s2, s3, s4
	op_count: 3
		operands[0].type: REG = s2
		operands[1].type: REG = s3
		operands[2].type: REG = s4

0x1078:	sub	s5, s6, s7
	op_count: 3
		operands[0].type: REG = s5
		operands[1].type: REG = s6
		operands[2].type: REG = s7

0x107c:	slt	s8, s9, s10
	op_count: 3
		operands[0].type: REG = s8
		operands[1].type: REG = s9
		operands[2].type: REG = s10

0x1080:	sltu	s11, t3, t4
	op_count: 3
		operands[0].type: REG = s11
		operands[1].type: REG = t3
		operands[2].type: REG = t4

0x1084:	sra	tp, t0, t1
	op_count: 3
		operands[0].type: REG = tp
		operands[1].type: REG = t0
		operands[2].type: REG = t1

0x1088:	xor	t2, s0, s1
	op_count: 3
		operands[0].type: REG = t2
		operands[1].type: REG = s0
		operands[2].type: REG = s1

0x108c:	or	a0, a1, a2
	op_count: 3
		operands[0].type: REG = a0
		operands[1].type: REG = a1
		operands[2].type: REG = a2

0x1090:	and	a3, a4, a5
	op_count: 3
		operands[0].type: REG = a3
		operands[1].type: REG = a4
		operands[2].type: REG = a5

0x1094:	srl	s1, s2, s3
	op_count: 3
		operands[0].type: REG = s1
		operands[1].type: REG = s2
		operands[2].type: REG = s3

0x1098:	srl	ra, sp, gp
	op_count: 3
		operands[0].type: REG = ra
		operands[1].type: REG = sp
		operands[2].type: REG = gp

0x109c:	sll	t5, t6, zero
	op_count: 3
		operands[0].type: REG = t5
		operands[1].type: REG = t6
		operands[2].type: REG = zero

0x10a0:

****************
Platform: riscv64
Code:0x13 0x04 0xa8 0x7a 
Disasm:
0x1000:	addi	s0, a6, 0x7aa
	op_count: 3
		operands[0].type: REG = s0
		operands[1].type: REG = a6
		operands[2].type: IMM = 0x7aa

0x1004:

