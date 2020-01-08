****************
Platform: TMS320C64x
Code:0x01 0xac 0x88 0x40 0x81 0xac 0x88 0x43 0x00 0x00 0x00 0x00 0x02 0x90 0x32 0x96 0x02 0x80 0x46 0x9e 0x05 0x3c 0x83 0xe6 0x0b 0x0c 0x8b 0x24 
Disasm:
0x1000:	add.D1	a11, a4, a3
	op_count: 3
		operands[0].type: REG = a11
		operands[1].type: REG = a4
		operands[2].type: REG = a3
	Functional unit: D1
	Parallel: false

0x1004:	[ a1] add.D2	b11, b4, b3	||
	op_count: 3
		operands[0].type: REG = b11
		operands[1].type: REG = b4
		operands[2].type: REG = b3
	Functional unit: D2
	Condition: [ a1]
	Parallel: true

0x1008:	NOP	
	Functional unit: No Functional Unit
	Parallel: false

0x100c:	ldbu.D1T2	*++a4[1], b5
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = a4
			operands[0].mem.disptype: Constant
			operands[0].mem.disp: 1
			operands[0].mem.unit: 2
			operands[0].mem.direction: Forward
			operands[0].mem.modify: Pre
			operands[0].mem.scaled: 1
		operands[1].type: REG = b5
	Functional unit: D2
	Parallel: false

0x1010:	ldbu.D2T2	*+b15[0x46], b5
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = b15
			operands[0].mem.disptype: Constant
			operands[0].mem.disp: 70
			operands[0].mem.unit: 2
			operands[0].mem.direction: Forward
			operands[0].mem.modify: No
			operands[0].mem.scaled: 0
		operands[1].type: REG = b5
	Functional unit: D2
	Parallel: false

0x1014:	lddw.D1T2	*+a15[4], b11:b10
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = a15
			operands[0].mem.disptype: Constant
			operands[0].mem.disp: 4
			operands[0].mem.unit: 2
			operands[0].mem.direction: Forward
			operands[0].mem.modify: No
			operands[0].mem.scaled: 1
		operands[1].type: REGPAIR = b11:b10
	Functional unit: D2
	Parallel: false

0x1018:	ldndw.D1T1	*+a3(a4), a23:a22
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = a3
			operands[0].mem.disptype: Register
			operands[0].mem.disp: a4
			operands[0].mem.unit: 1
			operands[0].mem.direction: Forward
			operands[0].mem.modify: No
			operands[0].mem.scaled: 0
		operands[1].type: REGPAIR = a23:a22
	Functional unit: D1
	Parallel: false

0x101c:

