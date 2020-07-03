---
title: "macho"
date: 2020-01-26T09:17:20-05:00
draft: false
weight: 8
summary: Parse a MachO file
---

## [WIP] 🚧

### Similar to `otool -h -l`

```bash
$ ipsw macho JavaScriptCore

Magic         = 64-bit MachO
Type          = Dylib
CPU           = AARCH64, ARM64e (ARMv8.3) caps: PAC00
Commands      = 25 (Size: 4384)
Flags         = NoUndefs, DyldLink, TwoLevel, BindsToWeak, NoReexportedDylibs, AppExtensionSafe
00: LC_SEGMENT_64 offset=0x00000000-0x00faf000, addr=0x1913da000-0x192389000	__TEXT
	offset=0x00001ae0-0x00ebb7f4, addr=0x1913dbae0-0x1922957f4		__TEXT.__text		PureInstructions|SomeInstructions
	offset=0x00ebb7f4-0x00ebd7e4, addr=0x1922957f4-0x1922977e4		__TEXT.__auth_stubs	(SymbolStubs)	PureInstructions|SomeInstructions
	offset=0x00ebd7e8-0x00ebe0dc, addr=0x1922977e8-0x1922980dc		__TEXT.__objc_methlist
	offset=0x00ebe0e0-0x00f16000, addr=0x1922980e0-0x1922f0000		__TEXT.__const
	offset=0x00f16000-0x00faba8b, addr=0x1922f0000-0x192385a8b		__TEXT.__cstring	(Cstring Literals)
	offset=0x00faba8c-0x00fad904, addr=0x192385a8c-0x192387904		__TEXT.__gcc_except_tab
	offset=0x00fad904-0x00fadf49, addr=0x192387904-0x192387f49		__TEXT.__oslogstring	(Cstring Literals)
	offset=0x00fadf4c-0x00faee74, addr=0x192387f4c-0x192388e74		__TEXT.__unwind_info
	offset=0x00000000-0x00000000, addr=0x192389000-0x192389000		__TEXT.__objc_classname	(Cstring Literals)
	offset=0x00000000-0x00000000, addr=0x192389000-0x192389000		__TEXT.__objc_methname	(Cstring Literals)
	offset=0x00000000-0x00000000, addr=0x192389000-0x192389000		__TEXT.__objc_methtype	(Cstring Literals)
01: LC_SEGMENT_64 offset=0x00faf000-0x00fba0c8, addr=0x1cf381a60-0x1cf38cb28	__DATA_CONST
	offset=0x00faf000-0x00faf250, addr=0x1cf381a60-0x1cf381cb0		__DATA_CONST.__got	(NonLazySymbolPointers)
	offset=0x00faf250-0x00fb9578, addr=0x1cf381cb0-0x1cf38bfd8		__DATA_CONST.__const
	offset=0x00fb9578-0x00fb95d0, addr=0x1cf38bfd8-0x1cf38c030		__DATA_CONST.__objc_classlist		NoDeadStrip
	offset=0x00fb95d0-0x00fb95d0, addr=0x1cf38c030-0x1cf38c030		__DATA_CONST.__objc_catlist		NoDeadStrip
	offset=0x00fb95d0-0x00fb95e8, addr=0x1cf38c030-0x1cf38c048		__DATA_CONST.__objc_protolist
	offset=0x00fb95e8-0x00fb95f0, addr=0x1cf38c048-0x1cf38c050		__DATA_CONST.__objc_imageinfo
	offset=0x00fb95f0-0x00fba0c8, addr=0x1cf38c050-0x1cf38cb28		__DATA_CONST.__objc_const
02: LC_SEGMENT_64 offset=0x00fba0c8-0x00fc6410, addr=0x1d29f4000-0x1d2a00348	__DATA
	offset=0x00fba0c8-0x00fba910, addr=0x1d29f4000-0x1d29f4848		__DATA.__objc_selrefs	(Literal Pointers)	NoDeadStrip
	offset=0x00fba910-0x00fbaa18, addr=0x1d29f4848-0x1d29f4950		__DATA.__objc_classrefs		NoDeadStrip
	offset=0x00fbaa18-0x00fbaa50, addr=0x1d29f4950-0x1d29f4988		__DATA.__objc_superrefs		NoDeadStrip
	offset=0x00fbaa50-0x00fbaad0, addr=0x1d29f4988-0x1d29f4a08		__DATA.__objc_ivar
	offset=0x00fbaad0-0x00fbaf58, addr=0x1d29f4a08-0x1d29f4e90		__DATA.__data
	offset=0x00000000-0x00008180, addr=0x1d29f8000-0x1d2a00180		__DATA.__common	(Zerofill)
	offset=0x00000000-0x000001c8, addr=0x1d2a00180-0x1d2a00348		__DATA.__bss	(Zerofill)
03: LC_SEGMENT_64 offset=0x00fc6410-0x00ff7dc8, addr=0x1d8a8d458-0x1d8abee10	__AUTH_CONST
	offset=0x00fc6410-0x00ff5f88, addr=0x1d8a8d458-0x1d8abcfd0		__AUTH_CONST.__const
	offset=0x00ff5f88-0x00ff6dc8, addr=0x1d8abcfd0-0x1d8abde10		__AUTH_CONST.__cfstring
	offset=0x00ff6dc8-0x00ff6dc8, addr=0x1d8abde10-0x1d8abde10		__AUTH_CONST.__objc_const
	offset=0x00ff6dc8-0x00ff7dc0, addr=0x1d8abde10-0x1d8abee08		__AUTH_CONST.__auth_got	(NonLazySymbolPointers)
	offset=0x00ff7dc0-0x00ff7dc8, addr=0x1d8abee08-0x1d8abee10		__AUTH_CONST.__got	(NonLazySymbolPointers)
04: LC_SEGMENT_64 offset=0x00ff7dc8-0x01000d78, addr=0x1db912c10-0x1db91bbc0	__DATA_DIRTY
	offset=0x00ff7dc8-0x00ff8098, addr=0x1db912c10-0x1db912ee0		__DATA_DIRTY.__objc_data
	offset=0x00ff8098-0x00ffbf80, addr=0x1db912ee0-0x1db916dc8		__DATA_DIRTY.__data
	offset=0x00000000-0x00003e00, addr=0x1db916dc8-0x1db91abc8		__DATA_DIRTY.__common	(Zerofill)
	offset=0x00000000-0x00000ff8, addr=0x1db91abc8-0x1db91bbc0		__DATA_DIRTY.__bss	(Zerofill)
05: LC_SEGMENT_64 offset=0x01000d78-0x010013a8, addr=0x1d8abee10-0x1d8abf440	__OBJC_CONST
	offset=0x01000d78-0x010013a8, addr=0x1d8abee10-0x1d8abf440		__OBJC_CONST.__objc_class_ro
06: LC_SEGMENT_64 offset=0x010013a8-0x01001450, addr=0x1dc210f58-0x1dc211000	__AUTH
	offset=0x010013a8-0x01001448, addr=0x1dc210f58-0x1dc210ff8		__AUTH.__objc_data
	offset=0x01001448-0x01001450, addr=0x1dc210ff8-0x1dc211000		__AUTH.__data
07: LC_SEGMENT_64 offset=0x01001450-0x0135907c, addr=0x1def74000-0x1df2cc000	__LINKEDIT
08: LC_ID_DYLIB                 /System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore (610.1.15)
09: LC_DYLD_EXPORTS_TRIE        Count: 0
10: LC_SYMTAB                   Symbol offset=0x0100C258, Num Syms: 30219, String offset=0x0108342C-0x0135907C
11: LC_DYSYMTAB                 1097 Indirect symbols at offset 0x01082308
12: LC_UUID                     0284D7B5-51DF-34C8-807F-BA431EBCAE1D
13: LC_BUILD_VERSION            Platform: iOS, SDK: 14.0.0, Tool: ld (607.2.0)
14: LC_SOURCE_VERSION           7610.1.15.50.3
15: LC_LOAD_DYLIB               /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation (1740.0.0)
16: LC_LOAD_DYLIB               /System/Library/Frameworks/Foundation.framework/Foundation (1740.0.0)
17: LC_LOAD_DYLIB               /usr/lib/libicucore.A.dylib (66.0.0)
18: LC_LOAD_DYLIB               /usr/lib/libobjc.A.dylib (228.0.0)
19: LC_LOAD_DYLIB               /usr/lib/libz.1.dylib (1.2.11)
20: LC_LOAD_DYLIB               /System/Library/Frameworks/Security.framework/Security (59711.0.0)
21: LC_LOAD_DYLIB               /usr/lib/libc++.1.dylib (904.4.0)
22: LC_LOAD_DYLIB               /usr/lib/libSystem.B.dylib (1291.0.0)
23: LC_FUNCTION_STARTS          offset=0x01001450-0x0100c258, size=44552, count=25787
24: LC_DATA_IN_CODE             offset=0x0100c258-0x0100c258, size=    0, entries=0

NOTE: recorded command size 4384, computed command size 4384
NOTE: File size is 20287612
```
