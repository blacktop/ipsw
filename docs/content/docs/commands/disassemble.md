---
title: "disass"
date: 2020-01-26T09:15:48-05:00
draft: false
weight: 13
summary: Disassemble ARMv8.5 binaries.
---

## [WIP] 🚧

Working on getting a disassembler working

```bash
$ ipsw disass --vaddr 0xfffffff007b7c05c kernelcache.release.iphone12.decompressed
```

```s
0xfffffff007b7c05c:	pacibsp
0xfffffff007b7c060:	stp		x24, x23, [sp, #-0x40]!
0xfffffff007b7c064:	stp		x22, x21, [sp, #0x10]
0xfffffff007b7c068:	stp		x20, x19, [sp, #0x20]
0xfffffff007b7c06c:	stp		x29, x30, [sp, #0x30]
0xfffffff007b7c070:	mov		x19, x3
0xfffffff007b7c074:	mov		x20, x2
0xfffffff007b7c078:	mov		x21, x1
0xfffffff007b7c07c:	mov		x22, x0
0xfffffff007b7c080:	sub		x23, x5, x4
0xfffffff007b7c084:	mov		x0, x23
0xfffffff007b7c088:	bl		#0xfffffff007b7c044
0xfffffff007b7c08c:	mov		w8, #0x2f
0xfffffff007b7c090:	sub		x8, x8, x22
0xfffffff007b7c094:	add		x8, x8, x21
0xfffffff007b7c098:	orr		x9, xzr, #0xaaaaaaaaaaaaaaaa
0xfffffff007b7c09c:	movk		x9, #0xaaab
0xfffffff007b7c0a0:	umulh		x9, x8, x9
0xfffffff007b7c0a4:	lsr		x9, x9, #5
0xfffffff007b7c0a8:	orr		w10, wzr, #0x30
...
```

You can also dissassemble a function by name

```bash
$ ipsw disass --symbol <SYMBOL_NAME> --instrs 200 JavaScriptCore
```

Make it pretty 💄🐷 using [bat](https://github.com/sharkdp/bat)

```bash
$ ipsw disass --vaddr 0xFFFFFFF007B44000 kernelcache.release.iphone13.decompressed \
   | bat -l s --tabs 0 -p --theme Nord --wrap=never --pager "less -S"
```

```s
func_fffffff007b44000:
0xfffffff007b44000:  5f 24 03 d5        bti             c
0xfffffff007b44004:  01 00 00 14        b               #0xfffffff007b44008

func_fffffff007b44008:
0xfffffff007b44008:  3f 05 40 f1        cmp             x9, #0x1, lsl #0xc
0xfffffff007b4400c:  ea 03 00 91        mov             x10, sp
0xfffffff007b44010:  c3 00 00 54        b.cc            #0xfffffff007b44028
0xfffffff007b44014:  4a 05 40 d1        sub             x10, x10, #0x1, lsl #0xc
0xfffffff007b44018:  5f 01 40 f9        ldr             xzr, [x10]
0xfffffff007b4401c:  29 05 40 d1        sub             x9, x9, #0x1, lsl #0xc
0xfffffff007b44020:  3f 05 40 f1        cmp             x9, #0x1, lsl #0xc
0xfffffff007b44024:  88 ff ff 54        b.hi            #0xfffffff007b44014
0xfffffff007b44028:  4a 01 09 cb        sub             x10, x10, x9
0xfffffff007b4402c:  5f 01 40 f9        ldr             xzr, [x10]
0xfffffff007b44030:  c0 03 5f d6        ret

func_fffffff007b44034:
0xfffffff007b44034:  20 50 8e d2        mov             x0, #0x7281
0xfffffff007b44038:  c0 ec ad f2        movk            x0, #0x6f66, lsl #0x10
0xfffffff007b4403c:  40 0e ce f2        movk            x0, #0x7072, lsl #0x20
0xfffffff007b44040:  80 ed ff f2        movk            x0, #0xff6c, lsl #0x30
0xfffffff007b44044:  c0 03 5f d6        ret
```

Demangle C++ names

```bash
$ ipsw disass --demangle --symbol <SYMBOL_NAME> --instrs 200 JavaScriptCore | bat -p -l s --tabs 0
```
