********************
Platform: M680X_HD6301
Code: 0x6b 0x10 0x00 0x71 0x10 0x00 0x72 0x10 0x10 0x39 
Disasm:
0x1000: 6b1000     tim   #16; 0, x
	op_count: 2
		operands[0].type: IMMEDIATE = #16
			size: 1
			access: READ
		operands[1].type: INDEXED
			base register: x
			offset: 0
			offset bits: 8
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc

0x1003: 711000     aim   #16, $00
	op_count: 2
		operands[0].type: IMMEDIATE = #16
			size: 1
			access: READ
		operands[1].type: DIRECT = 0x00
			size: 1
			access: READ | WRITE
	Registers read: cc
	Registers modified: cc

0x1006: 721010     oim   #16, $10
	op_count: 2
		operands[0].type: IMMEDIATE = #16
			size: 1
			access: READ
		operands[1].type: DIRECT = 0x10
			size: 1
			access: READ | WRITE
	Registers read: cc
	Registers modified: cc

0x1009: 39         rts   
	Registers read: s
	Registers modified: s pc
	groups_count: 1

********************
Platform: M680X_HD6309
Code: 0x01 0x10 0x10 0x62 0x10 0x10 0x7b 0x10 0x10 0x00 0xcd 0x49 0x96 0x02 0xd2 0x10 0x30 0x23 0x10 0x38 0x10 0x3b 0x10 0x53 0x10 0x5d 0x11 0x30 0x43 0x10 0x11 0x37 0x25 0x10 0x11 0x38 0x12 0x11 0x39 0x23 0x11 0x3b 0x34 0x11 0x8e 0x10 0x00 0x11 0xaf 0x10 0x11 0xab 0x10 0x11 0xf6 0x80 0x00 
Disasm:
0x1000: 011010     oim   #16, $10
	op_count: 2
		operands[0].type: IMMEDIATE = #16
			size: 1
			access: READ
		operands[1].type: DIRECT = 0x10
			size: 1
			access: READ | WRITE
	Registers read: cc
	Registers modified: cc

0x1003: 621010     aim   #16; -16, x
	op_count: 2
		operands[0].type: IMMEDIATE = #16
			size: 1
			access: READ
		operands[1].type: INDEXED
			base register: x
			offset: -16
			offset bits: 5
			size: 1
			access: READ | WRITE
	Registers read: cc x
	Registers modified: cc

0x1006: 7b101000   tim   #16, $1000
	op_count: 2
		operands[0].type: IMMEDIATE = #16
			size: 1
			access: READ
		operands[1].type: EXTENDED  = 0x1000
			size: 1
			access: READ
	Registers read: cc
	Registers modified: cc

0x100a: cd499602d2 ldq   #1234567890
	op_count: 2
		operands[0].type: REGISTER = q (in mnemonic)
			size: 4
			access: WRITE
		operands[1].type: IMMEDIATE = #1234567890
			size: 4
			access: READ
	Registers read: cc
	Registers modified: cc q

0x100f: 103023     addr  y, u
	op_count: 2
		operands[0].type: REGISTER = y
			size: 2
			access: READ
		operands[1].type: REGISTER = u
			size: 2
			access: READ | WRITE
	Registers read: cc y u
	Registers modified: cc u

0x1012: 1038       pshsw 
	op_count: 2
		operands[0].type: REGISTER = s (in mnemonic)
			size: 2
			access: READ | WRITE
		operands[1].type: REGISTER = w (in mnemonic)
			size: 2
			access: READ
	Registers read: s w
	Registers modified: s

0x1014: 103b       puluw 
	op_count: 2
		operands[0].type: REGISTER = u (in mnemonic)
			size: 2
			access: READ | WRITE
		operands[1].type: REGISTER = w (in mnemonic)
			size: 2
			access: WRITE
	Registers read: u
	Registers modified: u w

0x1016: 1053       comw  
	op_count: 1
		operands[0].type: REGISTER = w (in mnemonic)
			size: 2
			access: READ | WRITE
	Registers read: cc w
	Registers modified: cc w

0x1018: 105d       tstw  
	op_count: 1
		operands[0].type: REGISTER = w (in mnemonic)
			size: 2
			access: READ
	Registers read: cc w
	Registers modified: cc

0x101a: 11304310   band  a, 0, 3, $10
	op_count: 4
		operands[0].type: REGISTER = a
			size: 1
			access: READ | WRITE
		operands[1].type: CONSTANT = 0
			access: READ
		operands[2].type: CONSTANT = 3
			access: READ
		operands[3].type: DIRECT = 0x10
			size: 1
			access: READ
	Registers read: a
	Registers modified: a

0x101e: 11372510   stbt  cc, 4, 5, $10
	op_count: 4
		operands[0].type: REGISTER = cc
			size: 1
			access: READ
		operands[1].type: CONSTANT = 4
			access: READ
		operands[2].type: CONSTANT = 5
			access: READ
		operands[3].type: DIRECT = 0x10
			size: 1
			access: READ | WRITE
	Registers read: cc

0x1022: 113812     tfm   x+, y+
	op_count: 2
		operands[0].type: INDEXED
			base register: x
			post increment: 1
			size: 1
			access: READ
		operands[1].type: INDEXED
			base register: y
			post increment: 1
			size: 1
			access: WRITE
	Registers read: w x y
	Registers modified: w x y

0x1025: 113923     tfm   y-, u-
	op_count: 2
		operands[0].type: INDEXED
			base register: y
			post decrement: 1
			size: 1
			access: READ
		operands[1].type: INDEXED
			base register: u
			post decrement: 1
			size: 1
			access: WRITE
	Registers read: w y u
	Registers modified: w y u

0x1028: 113b34     tfm   u, s+
	op_count: 2
		operands[0].type: INDEXED
			base register: u
			size: 1
			access: READ
		operands[1].type: INDEXED
			base register: s
			post increment: 1
			size: 1
			access: WRITE
	Registers read: w u s
	Registers modified: w s

0x102b: 118e1000   divq  #4096
	op_count: 2
		operands[0].type: REGISTER = q (in mnemonic)
			size: 4
			access: READ | WRITE
		operands[1].type: IMMEDIATE = #4096
			size: 2
			access: READ
	Registers read: cc q
	Registers modified: cc q

0x102f: 11af10     muld  -16, x
	op_count: 2
		operands[0].type: REGISTER = d (in mnemonic)
			size: 2
			access: READ | WRITE
		operands[1].type: INDEXED
			base register: x
			offset: -16
			offset bits: 5
			size: 2
			access: READ
	Registers read: cc d x
	Registers modified: cc d w

0x1032: 11ab10     adde  -16, x
	op_count: 2
		operands[0].type: REGISTER = e (in mnemonic)
			size: 1
			access: READ | WRITE
		operands[1].type: INDEXED
			base register: x
			offset: -16
			offset bits: 5
			size: 1
			access: READ
	Registers read: cc e x
	Registers modified: cc e

0x1035: 11f68000   ldf   $8000
	op_count: 2
		operands[0].type: REGISTER = f (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: EXTENDED  = 0x8000
			size: 1
			access: READ
	Registers read: cc
	Registers modified: cc f

********************
Platform: M680X_M6800
Code: 0x01 0x09 0x36 0x64 0x7f 0x74 0x10 0x00 0x90 0x10 0xa4 0x10 0xb6 0x10 0x00 0x39 
Disasm:
0x1000: 01         nop   

0x1001: 09         dex   
	op_count: 1
		operands[0].type: REGISTER = x (in mnemonic)
			size: 2
			access: READ | WRITE
	Registers read: cc x
	Registers modified: cc x

0x1002: 36         psha  
	op_count: 1
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ
	Registers read: a s
	Registers modified: s

0x1003: 647f       lsr   127, x
	op_count: 1
		operands[0].type: INDEXED
			base register: x
			offset: 127
			offset bits: 8
			size: 1
			access: READ | WRITE
	Registers read: cc x
	Registers modified: cc

0x1005: 741000     lsr   $1000
	op_count: 1
		operands[0].type: EXTENDED  = 0x1000
			size: 1
			access: READ | WRITE
	Registers read: cc
	Registers modified: cc

0x1008: 9010       suba  $10
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ | WRITE
		operands[1].type: DIRECT = 0x10
			size: 1
			access: READ
	Registers read: cc a
	Registers modified: cc a

0x100a: a410       anda  16, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ | WRITE
		operands[1].type: INDEXED
			base register: x
			offset: 16
			offset bits: 8
			size: 1
			access: READ
	Registers read: cc a x
	Registers modified: cc a

0x100c: b61000     ldaa  $1000
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: EXTENDED  = 0x1000
			size: 1
			access: READ
	Registers read: cc
	Registers modified: cc a

0x100f: 39         rts   
	Registers read: s
	Registers modified: s pc
	groups_count: 1

********************
Platform: M680X_M6801
Code: 0x04 0x05 0x3c 0x3d 0x38 0x93 0x10 0xec 0x10 0xed 0x10 0x39 
Disasm:
0x1000: 04         lsrd  
	op_count: 1
		operands[0].type: REGISTER = d (in mnemonic)
			size: 2
			access: READ | WRITE
	Registers read: cc d
	Registers modified: cc d

0x1001: 05         asld  
	op_count: 1
		operands[0].type: REGISTER = d (in mnemonic)
			size: 2
			access: READ | WRITE
	Registers read: cc d
	Registers modified: cc d

0x1002: 3c         pshx  
	op_count: 1
		operands[0].type: REGISTER = x (in mnemonic)
			size: 2
			access: READ
	Registers read: x s
	Registers modified: s

0x1003: 3d         mul   
	Registers read: cc a b
	Registers modified: cc a b

0x1004: 38         pulx  
	op_count: 1
		operands[0].type: REGISTER = x (in mnemonic)
			size: 2
			access: WRITE
	Registers read: s
	Registers modified: x s

0x1005: 9310       subd  $10
	op_count: 2
		operands[0].type: REGISTER = d (in mnemonic)
			size: 2
			access: READ | WRITE
		operands[1].type: DIRECT = 0x10
			size: 2
			access: READ
	Registers read: cc d
	Registers modified: cc d

0x1007: ec10       ldd   16, x
	op_count: 2
		operands[0].type: REGISTER = d (in mnemonic)
			size: 2
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset: 16
			offset bits: 8
			size: 2
			access: READ
	Registers read: cc x
	Registers modified: cc d

0x1009: ed10       std   16, x
	op_count: 2
		operands[0].type: REGISTER = d (in mnemonic)
			size: 2
			access: READ
		operands[1].type: INDEXED
			base register: x
			offset: 16
			offset bits: 8
			size: 2
			access: WRITE
	Registers read: cc d x
	Registers modified: cc

0x100b: 39         rts   
	Registers read: s
	Registers modified: s pc
	groups_count: 1

********************
Platform: M680X_M68HC05
Code: 0x04 0x7f 0x00 0x17 0x22 0x28 0x00 0x2e 0x00 0x40 0x42 0x5a 0x70 0x8e 0x97 0x9c 0xa0 0x15 0xad 0x00 0xc3 0x10 0x00 0xda 0x12 0x34 0xe5 0x7f 0xfe 
Disasm:
0x1000: 047f00     brset 2, $7f, $1003
	op_count: 3
		operands[0].type: CONSTANT = 2
			access: READ
		operands[1].type: DIRECT = 0x7f
			size: 1
			access: READ
		operands[2].type: RELATIVE = 0x1003
	Registers read: cc
	Registers modified: cc
	groups_count: 2

0x1003: 1722       bset  3, $22
	op_count: 2
		operands[0].type: CONSTANT = 3
			access: READ
		operands[1].type: DIRECT = 0x22
			size: 1
			access: READ | WRITE

0x1005: 2800       bhcc  $1007
	op_count: 1
		operands[0].type: RELATIVE = 0x1007
	Registers read: cc
	groups_count: 2

0x1007: 2e00       bil   $1009
	op_count: 1
		operands[0].type: RELATIVE = 0x1009
	Registers read: cc
	groups_count: 2

0x1009: 40         nega  
	op_count: 1
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ | WRITE
	Registers read: cc a
	Registers modified: cc a

0x100a: 42         mul   
	Registers read: cc a x
	Registers modified: cc a x

0x100b: 5a         decx  
	op_count: 1
		operands[0].type: REGISTER = x (in mnemonic)
			size: 1
			access: READ | WRITE
	Registers read: cc x
	Registers modified: cc x

0x100c: 70         neg   , x
	op_count: 1
		operands[0].type: INDEXED
			base register: x
			size: 1
			access: READ | WRITE
	Registers read: cc x
	Registers modified: cc

0x100d: 8e         stop  

0x100e: 97         tax   
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ
		operands[1].type: REGISTER = x (in mnemonic)
			size: 1
			access: WRITE
	Registers read: a
	Registers modified: x

0x100f: 9c         rsp   
	op_count: 1
		operands[0].type: REGISTER = s (in mnemonic)
			size: 2
			access: WRITE
	Registers modified: s

0x1010: a015       sub   #21
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ | WRITE
		operands[1].type: IMMEDIATE = #21
			size: 1
			access: READ
	Registers read: cc a
	Registers modified: cc a

0x1012: ad00       bsr   $1014
	op_count: 1
		operands[0].type: RELATIVE = 0x1014
	Registers read: s
	Registers modified: s
	groups_count: 2

0x1014: c31000     cpx   $1000
	op_count: 2
		operands[0].type: REGISTER = x (in mnemonic)
			size: 1
			access: READ
		operands[1].type: EXTENDED  = 0x1000
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc

0x1017: da1234     ora   4660, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ | WRITE
		operands[1].type: INDEXED
			base register: x
			offset: 4660
			offset bits: 16
			size: 1
			access: READ
	Registers read: cc a x
	Registers modified: cc a

0x101a: e57f       bit   127, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ
		operands[1].type: INDEXED
			base register: x
			offset: 127
			offset bits: 8
			size: 1
			access: READ
	Registers read: cc a x
	Registers modified: cc

0x101c: fe         ldx   , x
	op_count: 2
		operands[0].type: REGISTER = x (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc x

********************
Platform: M680X_M68HC08
Code: 0x31 0x22 0x00 0x35 0x22 0x45 0x10 0x00 0x4b 0x00 0x51 0x10 0x52 0x5e 0x22 0x62 0x65 0x12 0x34 0x72 0x84 0x85 0x86 0x87 0x8a 0x8b 0x8c 0x94 0x95 0xa7 0x10 0xaf 0x10 0x9e 0x60 0x7f 0x9e 0x6b 0x7f 0x00 0x9e 0xd6 0x10 0x00 0x9e 0xe6 0x7f 
Disasm:
0x1000: 312200     cbeq  $22, $1003
	op_count: 3
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ
		operands[1].type: DIRECT = 0x22
			size: 1
			access: READ
		operands[2].type: RELATIVE = 0x1003
	Registers read: cc a
	groups_count: 2

0x1003: 3522       sthx  $22
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: READ
		operands[1].type: DIRECT = 0x22
			size: 2
			access: WRITE
	Registers read: cc hx
	Registers modified: cc

0x1005: 451000     ldhx  #4096
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: WRITE
		operands[1].type: IMMEDIATE = #4096
			size: 2
			access: READ
	Registers read: cc
	Registers modified: cc hx

0x1008: 4b00       dbnza $100a
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ | WRITE
		operands[1].type: RELATIVE = 0x100a
	Registers read: cc a
	Registers modified: a
	groups_count: 2

0x100a: 511052     cbeqx #16, $105f
	op_count: 3
		operands[0].type: REGISTER = x (in mnemonic)
			size: 1
			access: READ
		operands[1].type: IMMEDIATE = #16
			size: 1
			access: READ
		operands[2].type: RELATIVE = 0x105f
	Registers read: cc x
	groups_count: 2

0x100d: 5e22       mov   $22; x+
	op_count: 2
		operands[0].type: DIRECT = 0x22
			size: 1
			access: READ
		operands[1].type: INDEXED
			base register: x
			post increment: 1
			size: 1
			access: WRITE
	Registers read: cc x h
	Registers modified: cc x h

0x100f: 62         nsa   
	op_count: 1
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ | WRITE
	Registers read: cc a
	Registers modified: cc a

0x1010: 651234     cphx  #4660
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: READ
		operands[1].type: IMMEDIATE = #4660
			size: 2
			access: READ
	Registers read: cc hx
	Registers modified: cc

0x1013: 72         daa   
	Registers read: cc a
	Registers modified: cc a

0x1014: 84         tap   
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ
		operands[1].type: REGISTER = cc (in mnemonic)
			size: 1
			access: WRITE
	Registers read: a
	Registers modified: cc

0x1015: 85         tpa   
	op_count: 2
		operands[0].type: REGISTER = cc (in mnemonic)
			size: 1
			access: READ
		operands[1].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
	Registers read: cc
	Registers modified: a

0x1016: 86         pula  
	op_count: 1
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
	Registers read: s
	Registers modified: a s

0x1017: 87         psha  
	op_count: 1
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ
	Registers read: a s
	Registers modified: s

0x1018: 8a         pulh  
	op_count: 1
		operands[0].type: REGISTER = h (in mnemonic)
			size: 1
			access: WRITE
	Registers read: s
	Registers modified: h s

0x1019: 8b         pshh  
	op_count: 1
		operands[0].type: REGISTER = h (in mnemonic)
			size: 1
			access: READ
	Registers read: h s
	Registers modified: s

0x101a: 8c         clrh  
	op_count: 1
		operands[0].type: REGISTER = h (in mnemonic)
			size: 1
			access: WRITE
	Registers read: cc
	Registers modified: cc h

0x101b: 94         txs   
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: READ
		operands[1].type: REGISTER = s (in mnemonic)
			size: 2
			access: WRITE
	Registers read: hx
	Registers modified: s

0x101c: 95         tsx   
	op_count: 2
		operands[0].type: REGISTER = s (in mnemonic)
			size: 2
			access: READ
		operands[1].type: REGISTER = hx (in mnemonic)
			size: 2
			access: WRITE
	Registers read: s
	Registers modified: hx

0x101d: a710       ais   #16
	op_count: 2
		operands[0].type: REGISTER = s (in mnemonic)
			size: 2
			access: READ | WRITE
		operands[1].type: IMMEDIATE = #16
			size: 1
			access: READ
	Registers read: s
	Registers modified: s

0x101f: af10       aix   #16
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: READ | WRITE
		operands[1].type: IMMEDIATE = #16
			size: 1
			access: READ
	Registers read: hx
	Registers modified: hx

0x1021: 9e607f     neg   127, s
	op_count: 1
		operands[0].type: INDEXED
			base register: s
			offset: 127
			offset bits: 8
			size: 1
			access: READ | WRITE
	Registers read: cc s
	Registers modified: cc

0x1024: 9e6b7f00   dbnz  127, s; $1028
	op_count: 2
		operands[0].type: INDEXED
			base register: s
			offset: 127
			offset bits: 8
			size: 1
			access: READ | WRITE
		operands[1].type: RELATIVE = 0x1028
	Registers read: cc s
	groups_count: 2

0x1028: 9ed61000   lda   4096, s
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: s
			offset: 4096
			offset bits: 16
			size: 1
			access: READ
	Registers read: cc s
	Registers modified: cc a

0x102c: 9ee67f     lda   127, s
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: s
			offset: 127
			offset bits: 8
			size: 1
			access: READ
	Registers read: cc s
	Registers modified: cc a

********************
Platform: M680X_M6809
Code: 0x06 0x10 0x19 0x1a 0x55 0x1e 0x01 0x23 0xe9 0x31 0x06 0x34 0x55 0xa6 0x81 0xa7 0x89 0x7f 0xff 0xa6 0x9d 0x10 0x00 0xa7 0x91 0xa6 0x9f 0x10 0x00 0x11 0xac 0x99 0x10 0x00 0x39 0xa6 0x07 0xa6 0x27 0xa6 0x47 0xa6 0x67 0xa6 0x0f 0xa6 0x10 0xa6 0x80 0xa6 0x81 0xa6 0x82 0xa6 0x83 0xa6 0x84 0xa6 0x85 0xa6 0x86 0xa6 0x88 0x7f 0xa6 0x88 0x80 0xa6 0x89 0x7f 0xff 0xa6 0x89 0x80 0x00 0xa6 0x8b 0xa6 0x8c 0x10 0xa6 0x8d 0x10 0x00 0xa6 0x91 0xa6 0x93 0xa6 0x94 0xa6 0x95 0xa6 0x96 0xa6 0x98 0x7f 0xa6 0x98 0x80 0xa6 0x99 0x7f 0xff 0xa6 0x99 0x80 0x00 0xa6 0x9b 0xa6 0x9c 0x10 0xa6 0x9d 0x10 0x00 0xa6 0x9f 0x10 0x00 
Disasm:
0x1000: 0610       ror   $10
	op_count: 1
		operands[0].type: DIRECT = 0x10
			size: 1
			access: READ | WRITE
	Registers read: cc
	Registers modified: cc

0x1002: 19         daa   
	Registers read: cc a
	Registers modified: cc a

0x1003: 1a55       orcc  #85
	op_count: 2
		operands[0].type: REGISTER = cc (in mnemonic)
			size: 1
			access: READ | WRITE
		operands[1].type: IMMEDIATE = #85
			size: 1
			access: READ
	Registers read: cc
	Registers modified: cc

0x1005: 1e01       exg   d, x
	op_count: 2
		operands[0].type: REGISTER = d
			size: 2
			access: READ | WRITE
		operands[1].type: REGISTER = x
			size: 2
			access: READ | WRITE
	Registers read: d x
	Registers modified: d x

0x1007: 23e9       bls   $0ff2
	op_count: 1
		operands[0].type: RELATIVE = 0x0ff2
	Registers read: cc
	groups_count: 2

0x1009: 3106       leay  6, x
	op_count: 2
		operands[0].type: REGISTER = y (in mnemonic)
			size: 2
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset: 6
			offset bits: 5
			size: 2
			access: READ
	Registers read: cc x
	Registers modified: cc y

0x100b: 3455       pshs  cc, b, x, u
	op_count: 5
		operands[0].type: REGISTER = s (in mnemonic)
			size: 2
			access: READ | WRITE
		operands[1].type: REGISTER = cc
			size: 1
			access: READ
		operands[2].type: REGISTER = b
			size: 1
			access: READ
		operands[3].type: REGISTER = x
			size: 2
			access: READ
		operands[4].type: REGISTER = u
			size: 2
			access: READ
	Registers read: s cc b x u
	Registers modified: s

0x100d: a681       lda   , x++
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			post increment: 2
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a x

0x100f: a7897fff   sta   32767, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ
		operands[1].type: INDEXED
			base register: x
			offset: 32767
			offset bits: 16
			size: 1
			access: WRITE
	Registers read: cc a x
	Registers modified: cc

0x1013: a69d1000   lda   [$2017, pcr]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: pc
			offset: 4096
			offset address: 0x2017
			offset bits: 16
			size: 1
			access: READ
	Registers read: cc pc
	Registers modified: cc a

0x1017: a791       sta   [, x++]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ
		operands[1].type: INDEXED INDIRECT
			base register: x
			post increment: 2
			size: 1
			access: WRITE
	Registers read: cc a x
	Registers modified: cc x

0x1019: a69f1000   lda   [$1000]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: EXTENDED INDIRECT = 0x1000
			size: 1
			access: READ
	Registers read: cc
	Registers modified: cc a

0x101d: 11ac991000 cmps  [4096, x]
	op_count: 2
		operands[0].type: REGISTER = s (in mnemonic)
			size: 2
			access: READ
		operands[1].type: INDEXED INDIRECT
			base register: x
			offset: 4096
			offset bits: 16
			size: 2
			access: READ
	Registers read: cc s x
	Registers modified: cc

0x1022: 39         rts   
	Registers read: s
	Registers modified: s pc
	groups_count: 1

0x1023: a607       lda   7, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset: 7
			offset bits: 5
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a

0x1025: a627       lda   7, y
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: y
			offset: 7
			offset bits: 5
			size: 1
			access: READ
	Registers read: cc y
	Registers modified: cc a

0x1027: a647       lda   7, u
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: u
			offset: 7
			offset bits: 5
			size: 1
			access: READ
	Registers read: cc u
	Registers modified: cc a

0x1029: a667       lda   7, s
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: s
			offset: 7
			offset bits: 5
			size: 1
			access: READ
	Registers read: cc s
	Registers modified: cc a

0x102b: a60f       lda   15, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset: 15
			offset bits: 5
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a

0x102d: a610       lda   -16, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset: -16
			offset bits: 5
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a

0x102f: a680       lda   , x+
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			post increment: 1
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a x

0x1031: a681       lda   , x++
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			post increment: 2
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a x

0x1033: a682       lda   , -x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			pre decrement: 1
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a x

0x1035: a683       lda   , --x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			pre decrement: 2
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a x

0x1037: a684       lda   , x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a

0x1039: a685       lda   b, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset register: b
			size: 1
			access: READ
	Registers read: cc x b
	Registers modified: cc a

0x103b: a686       lda   a, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset register: a
			size: 1
			access: READ
	Registers read: cc x a
	Registers modified: cc a

0x103d: a6887f     lda   127, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset: 127
			offset bits: 8
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a

0x1040: a68880     lda   -128, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset: -128
			offset bits: 8
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a

0x1043: a6897fff   lda   32767, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset: 32767
			offset bits: 16
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a

0x1047: a6898000   lda   -32768, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset: -32768
			offset bits: 16
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a

0x104b: a68b       lda   d, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset register: d
			size: 1
			access: READ
	Registers read: cc x d
	Registers modified: cc a

0x104d: a68c10     lda   $1050, pcr
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: pc
			offset: 16
			offset address: 0x1050
			offset bits: 8
			size: 1
			access: READ
	Registers read: cc pc
	Registers modified: cc a

0x1050: a68d1000   lda   $2054, pcr
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: pc
			offset: 4096
			offset address: 0x2054
			offset bits: 16
			size: 1
			access: READ
	Registers read: cc pc
	Registers modified: cc a

0x1054: a691       lda   [, x++]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: x
			post increment: 2
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a x

0x1056: a693       lda   [, --x]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: x
			pre decrement: 2
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a x

0x1058: a694       lda   [, x]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: x
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a

0x105a: a695       lda   [b, x]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: x
			offset register: b
			size: 1
			access: READ
	Registers read: cc x b
	Registers modified: cc a

0x105c: a696       lda   [a, x]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: x
			offset register: a
			size: 1
			access: READ
	Registers read: cc x a
	Registers modified: cc a

0x105e: a6987f     lda   [127, x]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: x
			offset: 127
			offset bits: 8
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a

0x1061: a69880     lda   [-128, x]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: x
			offset: -128
			offset bits: 8
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a

0x1064: a6997fff   lda   [32767, x]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: x
			offset: 32767
			offset bits: 16
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a

0x1068: a6998000   lda   [-32768, x]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: x
			offset: -32768
			offset bits: 16
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc a

0x106c: a69b       lda   [d, x]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: x
			offset register: d
			size: 1
			access: READ
	Registers read: cc x d
	Registers modified: cc a

0x106e: a69c10     lda   [$1071, pcr]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: pc
			offset: 16
			offset address: 0x1071
			offset bits: 8
			size: 1
			access: READ
	Registers read: cc pc
	Registers modified: cc a

0x1071: a69d1000   lda   [$2075, pcr]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: pc
			offset: 4096
			offset address: 0x2075
			offset bits: 16
			size: 1
			access: READ
	Registers read: cc pc
	Registers modified: cc a

0x1075: a69f1000   lda   [$1000]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: EXTENDED INDIRECT = 0x1000
			size: 1
			access: READ
	Registers read: cc
	Registers modified: cc a

********************
Platform: M680X_M68HC11
Code: 0x02 0x03 0x12 0x7f 0x10 0x00 0x13 0x99 0x08 0x00 0x14 0x7f 0x02 0x15 0x7f 0x01 0x1e 0x7f 0x20 0x00 0x8f 0xcf 0x18 0x08 0x18 0x30 0x18 0x3c 0x18 0x67 0x18 0x8c 0x10 0x00 0x18 0x8f 0x18 0xce 0x10 0x00 0x18 0xff 0x10 0x00 0x1a 0xa3 0x7f 0x1a 0xac 0x1a 0xee 0x7f 0x1a 0xef 0x7f 0xcd 0xac 0x7f 
Disasm:
0x1000: 02         idiv  
	Registers read: cc d x
	Registers modified: cc d x

0x1001: 03         fdiv  
	Registers read: cc d x
	Registers modified: cc d x

0x1002: 127f1000   brset $7f, #16, $1006
	op_count: 3
		operands[0].type: DIRECT = 0x7f
			size: 1
			access: READ
		operands[1].type: IMMEDIATE = #16
			size: 1
			access: READ
		operands[2].type: RELATIVE = 0x1006
	Registers read: cc
	groups_count: 2

0x1006: 13990800   brclr $99, #8, $100a
	op_count: 3
		operands[0].type: DIRECT = 0x99
			size: 1
			access: READ
		operands[1].type: IMMEDIATE = #8
			size: 1
			access: READ
		operands[2].type: RELATIVE = 0x100a
	Registers read: cc
	groups_count: 2

0x100a: 147f02     bset  $7f, #2
	op_count: 2
		operands[0].type: DIRECT = 0x7f
			size: 1
			access: READ | WRITE
		operands[1].type: IMMEDIATE = #2
			size: 1
			access: READ
	Registers read: cc
	Registers modified: cc

0x100d: 157f01     bclr  $7f, #1
	op_count: 2
		operands[0].type: DIRECT = 0x7f
			size: 1
			access: READ | WRITE
		operands[1].type: IMMEDIATE = #1
			size: 1
			access: READ
	Registers read: cc
	Registers modified: cc

0x1010: 1e7f2000   brset 127, x; #32; $1014
	op_count: 3
		operands[0].type: INDEXED
			base register: x
			offset: 127
			offset bits: 8
			size: 1
			access: READ
		operands[1].type: IMMEDIATE = #32
			size: 1
			access: READ
		operands[2].type: RELATIVE = 0x1014
	Registers read: cc x
	groups_count: 2

0x1014: 8f         xgdx  
	op_count: 2
		operands[0].type: REGISTER = d (in mnemonic)
			size: 2
			access: READ | WRITE
		operands[1].type: REGISTER = x (in mnemonic)
			size: 2
			access: READ | WRITE
	Registers read: d x
	Registers modified: d x

0x1015: cf         stop  

0x1016: 1808       iny   
	op_count: 1
		operands[0].type: REGISTER = y (in mnemonic)
			size: 2
			access: READ | WRITE
	Registers read: cc y
	Registers modified: cc y

0x1018: 1830       tsy   
	op_count: 2
		operands[0].type: REGISTER = s (in mnemonic)
			size: 2
			access: READ
		operands[1].type: REGISTER = y (in mnemonic)
			size: 2
			access: WRITE
	Registers read: s
	Registers modified: y

0x101a: 183c       pshy  
	op_count: 1
		operands[0].type: REGISTER = y (in mnemonic)
			size: 2
			access: READ
	Registers read: y s
	Registers modified: s

0x101c: 186718     asr   24, y
	op_count: 1
		operands[0].type: INDEXED
			base register: y
			offset: 24
			offset bits: 8
			size: 1
			access: READ | WRITE
	Registers read: cc y
	Registers modified: cc

0x101f: 8c1000     cpx   #4096
	op_count: 2
		operands[0].type: REGISTER = x (in mnemonic)
			size: 2
			access: READ
		operands[1].type: IMMEDIATE = #4096
			size: 2
			access: READ
	Registers read: cc x
	Registers modified: cc

0x1022: 188f       xgdy  
	op_count: 2
		operands[0].type: REGISTER = d (in mnemonic)
			size: 2
			access: READ | WRITE
		operands[1].type: REGISTER = y (in mnemonic)
			size: 2
			access: READ | WRITE
	Registers read: d y
	Registers modified: d y

0x1024: 18ce1000   ldy   #4096
	op_count: 2
		operands[0].type: REGISTER = y (in mnemonic)
			size: 2
			access: WRITE
		operands[1].type: IMMEDIATE = #4096
			size: 2
			access: READ
	Registers read: cc
	Registers modified: cc y

0x1028: 18ff1000   sty   $1000
	op_count: 2
		operands[0].type: REGISTER = y (in mnemonic)
			size: 2
			access: READ
		operands[1].type: EXTENDED  = 0x1000
			size: 2
			access: WRITE
	Registers read: cc y
	Registers modified: cc

0x102c: 1aa37f     cpd   127, x
	op_count: 2
		operands[0].type: REGISTER = d (in mnemonic)
			size: 2
			access: READ
		operands[1].type: INDEXED
			base register: x
			offset: 127
			offset bits: 8
			size: 2
			access: READ
	Registers read: cc d x
	Registers modified: cc

0x102f: 1aac1a     cpy   26, x
	op_count: 2
		operands[0].type: REGISTER = y (in mnemonic)
			size: 2
			access: READ
		operands[1].type: INDEXED
			base register: x
			offset: 26
			offset bits: 8
			size: 2
			access: READ
	Registers read: cc y x
	Registers modified: cc

0x1032: ee7f       ldx   127, x
	op_count: 2
		operands[0].type: REGISTER = x (in mnemonic)
			size: 2
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset: 127
			offset bits: 8
			size: 2
			access: READ
	Registers read: cc x
	Registers modified: cc x

0x1034: 1aef7f     sty   127, x
	op_count: 2
		operands[0].type: REGISTER = y (in mnemonic)
			size: 2
			access: READ
		operands[1].type: INDEXED
			base register: x
			offset: 127
			offset bits: 8
			size: 2
			access: WRITE
	Registers read: cc y x
	Registers modified: cc

0x1037: cdac7f     cpx   127, y
	op_count: 2
		operands[0].type: REGISTER = x (in mnemonic)
			size: 2
			access: READ
		operands[1].type: INDEXED
			base register: y
			offset: 127
			offset bits: 8
			size: 2
			access: READ
	Registers read: cc x y
	Registers modified: cc

********************
Platform: M680X_CPU12
Code: 0x00 0x04 0x01 0x00 0x0c 0x00 0x80 0x0e 0x00 0x80 0x00 0x11 0x1e 0x10 0x00 0x80 0x00 0x3b 0x4a 0x10 0x00 0x04 0x4b 0x01 0x04 0x4f 0x7f 0x80 0x00 0x8f 0x10 0x00 0xb7 0x52 0xb7 0xb1 0xa6 0x67 0xa6 0xfe 0xa6 0xf7 0x18 0x02 0xe2 0x30 0x39 0xe2 0x10 0x00 0x18 0x0c 0x30 0x39 0x10 0x00 0x18 0x11 0x18 0x12 0x10 0x00 0x18 0x19 0x00 0x18 0x1e 0x00 0x18 0x3e 0x18 0x3f 0x00 
Disasm:
0x1000: 00         bgnd  

0x1001: 040100     dbeq  b, $1004
	op_count: 2
		operands[0].type: REGISTER = b
			size: 1
			access: READ | WRITE
		operands[1].type: RELATIVE = 0x1004
	Registers read: b
	Registers modified: b
	groups_count: 2

0x1004: 0c0080     bset  0, x; #-128
	op_count: 2
		operands[0].type: INDEXED
			base register: x
			offset: 0
			offset bits: 5
			size: 1
			access: READ | WRITE
		operands[1].type: IMMEDIATE = #-128
			size: 1
			access: READ
	Registers read: cc x
	Registers modified: cc

0x1007: 0e008000   brset 0, x; #-128; $100b
	op_count: 3
		operands[0].type: INDEXED
			base register: x
			offset: 0
			offset bits: 5
			size: 1
			access: READ
		operands[1].type: IMMEDIATE = #-128
			size: 1
			access: READ
		operands[2].type: RELATIVE = 0x100b
	Registers read: cc x
	groups_count: 2

0x100b: 11         ediv  
	Registers read: cc d y x
	Registers modified: cc d y

0x100c: 1e10008000 brset $1000, #-128, $1011
	op_count: 3
		operands[0].type: EXTENDED  = 0x1000
			size: 1
			access: READ
		operands[1].type: IMMEDIATE = #-128
			size: 1
			access: READ
		operands[2].type: RELATIVE = 0x1011
	Registers read: cc
	groups_count: 2

0x1011: 3b         pshd  
	op_count: 1
		operands[0].type: REGISTER = d (in mnemonic)
			size: 2
			access: READ
	Registers read: d s
	Registers modified: s

0x1012: 4a100004   call  $1000, 4
	op_count: 2
		operands[0].type: EXTENDED  = 0x1000
			size: 1
		operands[1].type: CONSTANT = 4
	Registers read: s
	Registers modified: s
	groups_count: 1

0x1016: 4b0104     call  1, x; 4
	op_count: 2
		operands[0].type: INDEXED
			base register: x
			offset: 1
			offset bits: 5
			size: 1
		operands[1].type: CONSTANT = 4
	Registers read: x s
	Registers modified: s
	groups_count: 1

0x1019: 4f7f8000   brclr $7f, #-128, $101d
	op_count: 3
		operands[0].type: DIRECT = 0x7f
			size: 1
			access: READ
		operands[1].type: IMMEDIATE = #-128
			size: 1
			access: READ
		operands[2].type: RELATIVE = 0x101d
	Registers read: cc
	groups_count: 2

0x101d: 8f1000     cps   #4096
	op_count: 2
		operands[0].type: REGISTER = s (in mnemonic)
			size: 2
			access: READ
		operands[1].type: IMMEDIATE = #4096
			size: 2
			access: READ
	Registers read: cc s
	Registers modified: cc

0x1020: b752       tfr   x, cc
	op_count: 2
		operands[0].type: REGISTER = x
			size: 2
			access: READ
		operands[1].type: REGISTER = cc
			size: 1
			access: WRITE
	Registers read: x
	Registers modified: cc

0x1022: b7b1       exg   tmp3, b
	op_count: 2
		operands[0].type: REGISTER = tmp3
			size: 2
			access: READ | WRITE
		operands[1].type: REGISTER = b
			size: 1
			access: READ | WRITE
	Registers read: tmp3 b
	Registers modified: tmp3 b

0x1024: a667       ldaa  8, +y
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: y
			pre increment: 8
			size: 1
			access: READ
	Registers read: cc y
	Registers modified: cc a y

0x1026: a6fe       ldaa  d, pc
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED
			base register: pc
			offset register: d
			size: 1
			access: READ
	Registers read: cc pc d
	Registers modified: cc a

0x1028: a6f7       ldaa  [d, s]
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: WRITE
		operands[1].type: INDEXED INDIRECT
			base register: s
			offset register: d
			size: 1
			access: READ
	Registers read: cc s d
	Registers modified: cc a

0x102a: 1802e23039e21000         movw  12345, x; 4096, x
	op_count: 2
		operands[0].type: INDEXED
			base register: x
			offset: 12345
			offset bits: 16
			size: 2
			access: READ
		operands[1].type: INDEXED
			base register: x
			offset: 4096
			offset bits: 16
			size: 2
			access: WRITE
	Registers read: x

0x1032: 180c30391000         movb  $3039, $1000
	op_count: 2
		operands[0].type: EXTENDED  = 0x3039
			size: 1
			access: READ
		operands[1].type: EXTENDED  = 0x1000
			size: 1
			access: WRITE

0x1038: 1811       fdiv  
	Registers read: cc d x
	Registers modified: cc d x

0x103a: 18121000   emacs $1000
	op_count: 1
		operands[0].type: EXTENDED  = 0x1000
			size: 4
			access: READ | WRITE
	Registers read: cc x y
	Registers modified: cc x

0x103e: 181900     mina  0, x
	op_count: 2
		operands[0].type: REGISTER = a (in mnemonic)
			size: 1
			access: READ | WRITE
		operands[1].type: INDEXED
			base register: x
			offset: 0
			offset bits: 5
			size: 1
			access: READ
	Registers read: cc a x
	Registers modified: cc a

0x1041: 181e00     emaxm 0, x
	op_count: 1
		operands[0].type: INDEXED
			base register: x
			offset: 0
			offset bits: 5
			size: 1
			access: READ | WRITE
	Registers read: cc x d
	Registers modified: cc

0x1044: 183e       stop  

0x1046: 183f00     etbl  0, x
	op_count: 1
		operands[0].type: INDEXED
			base register: x
			offset: 0
			offset bits: 5
			size: 1
			access: READ
	Registers read: cc x b
	Registers modified: cc a b

********************
Platform: M680X_HCS08
Code: 0x32 0x10 0x00 0x9e 0xae 0x9e 0xce 0x7f 0x9e 0xbe 0x10 0x00 0x9e 0xfe 0x7f 0x3e 0x10 0x00 0x9e 0xf3 0x7f 0x96 0x10 0x00 0x9e 0xff 0x7f 0x82 
Disasm:
0x1000: 321000     ldhx  $1000
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: WRITE
		operands[1].type: EXTENDED  = 0x1000
			size: 2
			access: READ
	Registers read: cc
	Registers modified: cc hx

0x1003: 9eae       ldhx  , x
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			size: 2
			access: READ
	Registers read: cc x h
	Registers modified: cc hx

0x1005: 9ece7f     ldhx  127, x
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset: 127
			offset bits: 8
			size: 2
			access: READ
	Registers read: cc x h
	Registers modified: cc hx

0x1008: 9ebe1000   ldhx  4096, x
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: WRITE
		operands[1].type: INDEXED
			base register: x
			offset: 4096
			offset bits: 16
			size: 2
			access: READ
	Registers read: cc x h
	Registers modified: cc hx

0x100c: 9efe7f     ldhx  127, s
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: WRITE
		operands[1].type: INDEXED
			base register: s
			offset: 127
			offset bits: 8
			size: 2
			access: READ
	Registers read: cc s
	Registers modified: cc hx

0x100f: 3e1000     cphx  $1000
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: READ
		operands[1].type: EXTENDED  = 0x1000
			size: 2
			access: READ
	Registers read: cc hx
	Registers modified: cc

0x1012: 9ef37f     cphx  127, s
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: READ
		operands[1].type: INDEXED
			base register: s
			offset: 127
			offset bits: 8
			size: 2
			access: READ
	Registers read: cc hx s
	Registers modified: cc

0x1015: 961000     sthx  $1000
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: READ
		operands[1].type: EXTENDED  = 0x1000
			size: 2
			access: WRITE
	Registers read: cc hx
	Registers modified: cc

0x1018: 9eff7f     sthx  127, s
	op_count: 2
		operands[0].type: REGISTER = hx (in mnemonic)
			size: 2
			access: READ
		operands[1].type: INDEXED
			base register: s
			offset: 127
			offset bits: 8
			size: 2
			access: WRITE
	Registers read: cc hx s
	Registers modified: cc

0x101b: 82         bgnd  

