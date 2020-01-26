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

HEADER
======
Magic         = 64-bit MachO
Type          = Dylib
CPU           = AARCH64, ARM64e (ARMv8.3)
Commands      = 22 (Size: 3800)
Flags         = NoUndefs, DyldLink, TwoLevel, BindsToWeak, NoReexportedDylibs, AppExtensionSafe

SECTIONS
========
Mem: 0x18f5a1470-0x1902aa548   __TEXT.__text                                             PureInstructions|SomeInstructions
Mem: 0x1902aa548-0x1902ac478   __TEXT.__auth_stubs             (SymbolStubs)             PureInstructions|SomeInstructions
Mem: 0x1902ac480-0x19030e080   __TEXT.__const
Mem: 0x19030e080-0x19039782a   __TEXT.__cstring                (Cstring Literals)
Mem: 0x19039782a-0x190397d95   __TEXT.__oslogstring            (Cstring Literals)
Mem: 0x190397d98-0x190399c04   __TEXT.__gcc_except_tab
Mem: 0x190399c04-0x19039ab18   __TEXT.__unwind_info
Mem: 0x19039b000-0x19039b000   __TEXT.__objc_classname         (Cstring Literals)
Mem: 0x19039b000-0x19039b000   __TEXT.__objc_methname          (Cstring Literals)
Mem: 0x19039b000-0x19039b000   __TEXT.__objc_methtype          (Cstring Literals)
<SNIP>
```