****************
Platform: MOS65XX_6502
Code: 0xa1 0x12 0xa5 0x12 0xa9 0x12 0xad 0x34 0x12 0xb1 0x12 0xb5 0x12 0xb9 0x34 0x12 0xbd 0x34 0x12 0x0d 0x34 0x12 0x00 0x81 0x87 0x6c 0x01 0x00 0x85 0xff 0x10 0x00 0x19 0x42 0x42 0x00 0x49 0x42
Disasm:
0x1000:	lda	($12, x)
	address mode: zero page indexed with x indirect
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x12

0x1002:	lda	$12
	address mode: zero page
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x12

0x1004:	lda	#$12
	address mode: immediate value
	modifies flags: true
	op_count: 1
		operands[0].type: IMM = 0x12

0x1006:	lda	$1234
	address mode: absolute
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x1234

0x1009:	lda	($12), y
	address mode: zero page indirect indexed with y
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x12

0x100b:	lda	$12, x
	address mode: zero page indexed with x
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x12

0x100d:	lda	$1234, y
	address mode: absolute indexed with y
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x1234

0x1010:	lda	$1234, x
	address mode: absolute indexed with x
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x1234

0x1013:	ora	$1234
	address mode: absolute
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x1234

0x1016:	brk	$81
	address mode: interrupt signature
	modifies flags: false
	op_count: 1
		operands[0].type: MEM = 0x81

0x1018:

****************
Platform: MOS65XX_65C02
Code: 0x1a 0x3a 0x02 0x12 0x03 0x5c 0x34 0x12
Disasm:
0x1000:	inc	a
	address mode: accumulator
	modifies flags: true
	op_count: 1
		operands[0].type: REG = A

0x1001:	dec	a
	address mode: accumulator
	modifies flags: true
	op_count: 1
		operands[0].type: REG = A

0x1002:	nop	
	address mode: implied
	modifies flags: false

0x1004:	nop	
	address mode: implied
	modifies flags: false

0x1005:	nop	
	address mode: implied
	modifies flags: false

0x1008:

****************
Platform: MOS65XX_W65C02
Code: 0x07 0x12 0x27 0x12 0x47 0x12 0x67 0x12 0x87 0x12 0xa7 0x12 0xc7 0x12 0xe7 0x12 0x0f 0x12 0xfd 0x4f 0x12 0xfd 0x8f 0x12 0xfd 0xcf 0x12 0xfd
Disasm:
0x1000:	rmb0	$12
	address mode: zero page
	modifies flags: false
	op_count: 1
		operands[0].type: MEM = 0x12

0x1002:	rmb2	$12
	address mode: zero page
	modifies flags: false
	op_count: 1
		operands[0].type: MEM = 0x12

0x1004:	rmb4	$12
	address mode: zero page
	modifies flags: false
	op_count: 1
		operands[0].type: MEM = 0x12

0x1006:	rmb6	$12
	address mode: zero page
	modifies flags: false
	op_count: 1
		operands[0].type: MEM = 0x12

0x1008:	smb0	$12
	address mode: zero page
	modifies flags: false
	op_count: 1
		operands[0].type: MEM = 0x12

0x100a:	smb2	$12
	address mode: zero page
	modifies flags: false
	op_count: 1
		operands[0].type: MEM = 0x12

0x100c:	smb4	$12
	address mode: zero page
	modifies flags: false
	op_count: 1
		operands[0].type: MEM = 0x12

0x100e:	smb6	$12
	address mode: zero page
	modifies flags: false
	op_count: 1
		operands[0].type: MEM = 0x12

0x1010:	bbr0	$12, $1010
	address mode: relative bit branch
	modifies flags: false
	op_count: 2
		operands[0].type: MEM = 0x12
		operands[1].type: MEM = 0xfd

0x1013:	bbr4	$12, $1013
	address mode: relative bit branch
	modifies flags: false
	op_count: 2
		operands[0].type: MEM = 0x12
		operands[1].type: MEM = 0xfd

0x1016:	bbs0	$12, $1016
	address mode: relative bit branch
	modifies flags: false
	op_count: 2
		operands[0].type: MEM = 0x12
		operands[1].type: MEM = 0xfd

0x1019:	bbs4	$12, $1019
	address mode: relative bit branch
	modifies flags: false
	op_count: 2
		operands[0].type: MEM = 0x12
		operands[1].type: MEM = 0xfd

0x101c:

****************
Platform: MOS65XX_65816 (long m/x)
Code: 0xa9 0x34 0x12 0xad 0x34 0x12 0xbd 0x34 0x12 0xb9 0x34 0x12 0xaf 0x56 0x34 0x12 0xbf 0x56 0x34 0x12 0xa5 0x12 0xb5 0x12 0xb2 0x12 0xa1 0x12 0xb1 0x12 0xa7 0x12 0xb7 0x12 0xa3 0x12 0xb3 0x12 0xc2 0x00 0xe2 0x00 0x54 0x34 0x12 0x44 0x34 0x12 0x02 0x12
Disasm:
0x1000:	lda	#$1234
	address mode: immediate value
	modifies flags: true
	op_count: 1
		operands[0].type: IMM = 0x1234

0x1003:	lda	$1234
	address mode: absolute
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x1234

0x1006:	lda	$1234, x
	address mode: absolute indexed with x
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x1234

0x1009:	lda	$1234, y
	address mode: absolute indexed with y
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x1234

0x100c:	lda	$123456
	address mode: absolute long
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x123456

0x1010:	lda	$123456, x
	address mode: absolute long indexed with x
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x123456

0x1014:	lda	$12
	address mode: zero page
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x12

0x1016:	lda	$12, x
	address mode: zero page indexed with x
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x12

0x1018:	lda	($12)
	address mode: zero page indirect
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x12

0x101a:	lda	($12, x)
	address mode: zero page indexed with x indirect
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x12

0x101c:	lda	($12), y
	address mode: zero page indirect indexed with y
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x12

0x101e:	lda	[$12]
	address mode: zero page indirect long
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x12

0x1020:	lda	[$12], y
	address mode: zero page indirect long indexed with y
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x12

0x1022:	lda	$12, s
	address mode: stack relative
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x12

0x1024:	lda	($12, s), y
	address mode: stack relative indirect indexed with y
	modifies flags: true
	op_count: 1
		operands[0].type: MEM = 0x12

0x1026:	rep	#$00
	address mode: immediate value
	modifies flags: true
	op_count: 1
		operands[0].type: IMM = 0x0

0x1028:	sep	#$00
	address mode: immediate value
	modifies flags: true
	op_count: 1
		operands[0].type: IMM = 0x0

0x102a:	mvn	$12, $34
	address mode: block move
	modifies flags: false
	op_count: 2
		operands[0].type: MEM = 0x12
		operands[1].type: MEM = 0x34

0x102d:	mvp	$12, $34
	address mode: block move
	modifies flags: false
	op_count: 2
		operands[0].type: MEM = 0x12
		operands[1].type: MEM = 0x34

0x1030:	cop	$12
	address mode: interrupt signature
	modifies flags: false
	op_count: 1
		operands[0].type: MEM = 0x12

0x1032:

