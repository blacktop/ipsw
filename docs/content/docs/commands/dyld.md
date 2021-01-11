---
title: "dyld"
date: 2020-01-26T09:17:35-05:00
draft: false
weight: 10
summary: Parse dyld_shared_cache.
---

- [**dyld info**](#dyld-info)
- [**dyld extract**](#dyld-extract)
- [**dyld macho**](#dyld-macho)
- [**dyld symaddr**](#dyld-symaddr)
- [**dyld a2s**](#dyld-a2s)
- [**dyld objc**](#dyld-objc)
  - [**dyld objc class**](#dyld-objc-class)
  - [**dyld objc proto**](#dyld-objc-proto)
  - [**dyld objc sel**](#dyld-objc-sel)
- [**dyld split**](#dyld-split)
- [**dyld webkit**](#dyld-webkit)
- [**dyld patches** 🆕](#dyld-patches-)
- [**dyld a2o**](#dyld-a2o)
- [**dyld o2a**](#dyld-o2a)
- [**dyld disass**](#dyld-disass)

---

### **dyld info**

Similar to `jtool -h -l dyld_shared_cache`

```bash
$ ipsw dyld info -l -s dyld_shared_cache | head -n35

Header
======
Magic            = "dyld_v1  arm64e"
UUID             = 92537455-A74B-3198-96CD-F2D2D2778315
Platform         = iOS
Format           = 10 (BuiltFromChainedFixups)
Max Slide        = 0x33940000 (ASLR entropy: 16-bits)

Local Symbols (nlist array):     78MB,  offset:  0x62144260 -> 0x66F98340
Local Symbols (string pool):    256MB,  offset:  0x66F98340 -> 0x7701333B
Code Signature:                   3MB,  offset:  0x77014000 -> 0x773D0000
ImagesText Info (2072 entries):  64KB,  offset:  0x00000300 -> 0x00010600
Slide Info (v3):                  0KB,  offset:  0x00000000 -> 0x00000000
Branch Pool:                      0MB,  offset:  0x00000000 -> 0x00000000
Accelerate Tab:                   0KB,  address: 0x00000000 -> 0x00000000
Patch Info:                     512KB,  address: 0x1E798654C -> 0x1E7A068BC
Closures:                         6MB,  address: 0x1E7AE0000 -> 0x1E8129748
Closures Trie:                   53KB,  address: 0x1E8129748 -> 0x1E8136D40
Shared Region:                    4GB,  address: 0x180000000 -> 0x280000000

Mappings
========
|    SEG     | INITPROT | MAXPROT |  SIZE   |        ADDRESS         |     FILE OFFSET      |  SLIDE INFO OFFSET   | FLAGS |
|------------|----------|---------|---------|------------------------|----------------------|----------------------|-------|
| __TEXT     | r-x      | r-x     | 1222 MB | 180000000 -> 1CC6C0000 | 00000000 -> 4C6C0000 | 00000000 -> 00000000 | 0     |
| __DATA     | rw-      | rw-     | 116 MB  | 1CE6C0000 -> 1D5B18000 | 4C6C0000 -> 53B18000 | 58CA4000 -> 58CB4000 | 0     |
| __AUTH     | rw-      | rw-     | 81 MB   | 1D7B18000 -> 1DCCA4000 | 53B18000 -> 58CA4000 | 58CB8000 -> 58CC4000 | 1     |
| __LINKEDIT | r--      | r--     | 148 MB  | 1DECA4000 -> 1E8138000 | 58CA4000 -> 62138000 | 00000000 -> 00000000 | 0     |

Code Signature
==============
Code Directory (3963356 bytes)
	Version:     ExecSeg
	Flags:       Adhoc
	CodeLimit:   0x78f24000
	Identifier:  com.apple.dyld.cache.arm64e.release (@0x58)
	TeamID:
	CDHash:      7d32d18703679ac152a74ff872e38dda69339eabe29a0a6837861cec3d05de87 (computed)
	# of hashes: 123849 code (16384 pages) + 2 special
	Hashes @188 size: 32 Type: Sha256
Requirement Set (12 bytes) with 1 requirement
	0: 0x0 (@0, 12 bytes): empty requirement set

Images
======
   1: 0x180045000 /usr/lib/system/libsystem_trace.dylib                                                           (1264.0.0)
   2: 0x18005C000 /usr/lib/system/libxpc.dylib                                                                    (2001.0.0)
   3: 0x180091000 /usr/lib/system/libsystem_blocks.dylib                                                          (76.0.0)
   4: 0x180093000 /usr/lib/system/libsystem_c.dylib                                                               (1431.0.0)
```

**NOTE:** We added the `-s` or `--sig` flag to also parse the _CodeDirectory_.

### **dyld extract**

Extract _dyld_shared_cache_ from a previously downloaded _ipsw_

- `macOS`

```bash
$ ipsw dyld extract iPhone11,2_12.0_16A366_Restore.ipsw
   • Extracting dyld_shared_cache from IPSW
   • Mounting DMG
   • Extracting System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e to dyld_shared_cache
   • Unmounting DMG
```

- `docker`

```bash
$ docker run --init -it --rm \
             --device /dev/fuse \
             --cap-add=SYS_ADMIN \
             -v `pwd` :/data \
             blacktop/ipsw -V dyld extract iPhone11_2_12.4.1_16G102_Restore.ipsw
```

### **dyld macho**

Parse a dyld*shared_cache dylib *(same as ipsw macho cmd)\_

```bash
$ ipsw dyld macho dyld_shared_cache JavaScriptCore

Magic         = 64-bit MachO
Type          = Dylib
CPU           = AARCH64, ARM64e caps: PAC00
Commands      = 25 (Size: 4464)
Flags         = NoUndefs, DyldLink, TwoLevel, BindsToWeak, NoReexportedDylibs, AppExtensionSafe, DylibInCache
000: LC_SEGMENT_64 sz=0x01131000 off=0x09e18000-0x0af49000 addr=0x189e18000-0x18af49000 r-x/r-x   __TEXT
        sz=0x00ed4e18 off=0x09e19290-0x0acee0a8 addr=0x189e19290-0x18acee0a8            __TEXT.__text                   PureInstructions|SomeInstructions
        sz=0x00002000 off=0x0acee0a8-0x0acf00a8 addr=0x18acee0a8-0x18acf00a8            __TEXT.__auth_stubs             PureInstructions|SomeInstructions (SymbolStubs)
<SNIP>
```

### **dyld symaddr**

Find all instances of a symbol's _(unslid)_ addresses in shared cache

```bash
$ ipsw dyld symaddr dyld_shared_cache <SYMBOL_NAME>
```

Speed it up by supplying the dylib name

```bash
$ ipsw dyld symaddr --image JavaScriptCore dyld_shared_cache <SYMBOL_NAME>
```

**NOTE:** you don't have to supply the full image path

Dump ALL teh symbolz!!!

```bash
$ ipsw dyld symaddr dyld_shared_cache
```

### **dyld a2s**

Lookup what symbol is at a given _unslid_ address _(in hex)_

```bash
$ ipsw dyld a2s dyld_shared_cache 0x190a7221c
   • parsing public symbols...
   • parsing private symbols...
0x190a7221c: _xmlCtxtGetLastError
```

This will also create a cached version of the lookup hash table so the next time you lookup it will be much faster

```bash
$ time dist/ipsw_darwin_amd64/ipsw dyld a2s dyld_shared_cache 0x190a7221c
   • parsing public symbols...
   • parsing private symbols...
0x190a7221c: _xmlCtxtGetLastError
61.59s user 9.80s system 233% cpu "30.545 total"
```

```bash
$ time ipsw dyld a2s dyld_shared_cache 0x190a7221c
0x190a7221c: _xmlCtxtGetLastError
2.12s user 0.51s system 109% cpu "2.407 total"
```

### **dyld objc**

#### Dump ObjC addresses

Dump all the classes

```bash
$ ipsw dyld objc --class dyld_shared_cache
```

Dump all the protocols

```bash
$ ipsw dyld objc --proto dyld_shared_cache
```

Dump all the selectors

```bash
$ ipsw dyld objc --sel dyld_shared_cache
```

Dump all the imp-caches

```bash
$ ipsw dyld objc --imp-cache dyld_shared_cache
```

### **dyld objc class**

Lookup a class's address

```bash
$ ipsw dyld objc class dyld_shared_cache release

0x1b92c85a8: release
```

Or get all the classes for an image

```bash
$ ipsw dyld objc class --image libobjc.A.dylib dyld_shared_cache
```

### **dyld objc proto**

Lookup a protocol's address

```bash
$ ipsw dyld objc proto dyld_shared_cache release

0x1b92c85a8: release
```

Or get all the protocols for an image

```bash
$ ipsw dyld objc proto --image libobjc.A.dylib dyld_shared_cache
```

### **dyld objc sel**

Lookup a selector's address

```bash
$ ipsw dyld objc sel dyld_shared_cache release

0x1b92c85a8: release
```

Or get all the selectors for an image

```bash
$ ipsw dyld objc sel --image libobjc.A.dylib iPhone12,1_N104AP_18A5319i/dyld_shared_cache

Objective-C Selectors:
/usr/lib/libobjc.A.dylib
    0x1c9dcc5fd: instanceMethodSignatureForSelector:
    0x1c8f14de2: instanceMethodForSelector:
    0x1c9d3be7d: instancesRespondToSelector:
    0x1c8f113e9: isAncestorOfObject:
    0x1c9e91b48: isSubclassOfClass:
    0x1c90fe47d: name
    0x1c9aa0937: descriptionForClassMethod:
    0x1c9a01891: descriptionForInstanceMethod:
    0x1c9aaf8c2: conformsTo:
    0x1c8ef287d: 🤯 <========== WTF??
    0x1c93562fd: release
    0x1c9b2c9fd: initialize
<SNIP>
```

### **dyld split**

_(only on macOS and requires XCode to be installed)_

Split up a _dyld_shared_cache_

```bash
$ ipsw dyld split dyld_shared_cache .
   • Splitting dyld_shared_cache

0/1445
1/1445
2/1445
3/1445
<SNIP>
1441/1445
1442/1445
1443/1445
1444/1445
```

### **dyld webkit**

Extract WebKit version from _dyld_shared_cache_

```bash
$ ipsw dyld webkit --rev dyld_shared_cache
   • WebKit Version: 609.1.17.0.1 (svn rev 256416)
```

### **dyld patches** 🆕

List dyld patch info

```bash
$ ipsw dyld patches dyld_shared_cache | grep entries
   • [68 entries] /usr/lib/system/libsystem_c.dylib
   • [243 entries] /usr/lib/system/libdispatch.dylib
   • [13 entries] /usr/lib/system/libsystem_malloc.dylib
   • [3 entries] /usr/lib/system/libsystem_platform.dylib
   • [8 entries] /usr/lib/system/libsystem_pthread.dylib
   • [6 entries] /usr/lib/libobjc.A.dylib
   • [23 entries] /usr/lib/libc++abi.dylib
   • [45 entries] /usr/lib/system/libsystem_kernel.dylib
   • [2 entries] /usr/lib/system/libdyld.dylib
```

```bash
$ ipsw dyld patches dyld_shared_cache -i libdyld.dylib
0x0028074C (63 patches)  _dlclose
0x00280820 (399 patches) _dlopen
```

```bash
$ ipsw dyld patches dyld_shared_cache -i libdyld.dylib -s _dlopen | head
   • _dlopen patch locations
offset: 0x57b18898, addend: 0, diversity: 0x0000, key: IA, auth: true
offset: 0x57b19170, addend: 0, diversity: 0x0000, key: IA, auth: true
offset: 0x57b1ec20, addend: 0, diversity: 0x0000, key: IA, auth: true
offset: 0x57b345f8, addend: 0, diversity: 0x0000, key: IA, auth: true
offset: 0x57b38a50, addend: 0, diversity: 0x0000, key: IA, auth: true
offset: 0x57b3cd08, addend: 0, diversity: 0x0000, key: IA, auth: true
offset: 0x57b3db98, addend: 0, diversity: 0x0000, key: IA, auth: true
offset: 0x57b79850, addend: 0, diversity: 0x0000, key: IA, auth: true
offset: 0x57b88138, addend: 0, diversity: 0x0000, key: IA, auth: true
offset: 0x57bb56a8, addend: 0, diversity: 0x0000, key: IA, auth: true
```

### **dyld a2o**

Convert _dyld_shared_cache_ address to offset

```bash
ipsw dyld a2o dyld_shared_cache 1D7B18000

0x053b18000
```

### **dyld o2a**

Convert _dyld_shared_cache_ offset to address

```bash
ipsw dyld a2o dyld_shared_cache 0x4C6C0000

0x1ce6c0000
```

### **dyld disass**

Disassemble a function in the _dyld_shared_cache_

```bash
$ ipsw dyld disass --image Foundation dyld_shared_cache _NSLog

   • Found dyld_shared_cache companion symbol map file...
   • Locating symbol: _NSLog
   • Found symbol              dylib=/System/Library/Frameworks/Foundation.framework/Foundation
   • Parsing ObjC runtime structures...
   • Parsing MachO symbol stubs...
   • Parsing MachO global offset table...
```

> **NOTE:** You can speed up symbol lookups by supplying the `--image` flag

```s
_NSLog:
0x1808b9930:  7f 23 03 d5       pacibsp
0x1808b9934:  ff 83 00 d1       sub             sp, sp, #0x20
0x1808b9938:  fd 7b 01 a9       stp             x29, x30, [sp, #0x10]
0x1808b993c:  fd 43 00 91       add             x29, sp, #0x10
0x1808b9940:  88 4d 27 f0       adrp            x8, #0x1cf26c000
0x1808b9944:  08 5d 46 f9       ldr             x8, [x8, #0xcb8] ; __got.___stack_chk_guard
0x1808b9948:  08 01 40 f9       ldr             x8, [x8]
0x1808b994c:  e8 07 00 f9       str             x8, [sp, #0x8]
0x1808b9950:  a8 43 00 91       add             x8, x29, #0x10
0x1808b9954:  e8 03 00 f9       str             x8, [sp]
0x1808b9958:  e2 03 1e aa       mov             x2, x30
0x1808b995c:  e2 43 c1 da       xpaci           x2
0x1808b9960:  a1 43 00 91       add             x1, x29, #0x10
0x1808b9964:  d2 ff ff 97       bl              __NSLogv
0x1808b9968:  e8 07 40 f9       ldr             x8, [sp, #0x8]
0x1808b996c:  89 4d 27 f0       adrp            x9, #0x1cf26c000
0x1808b9970:  29 5d 46 f9       ldr             x9, [x9, #0xcb8] ; __got.___stack_chk_guard
0x1808b9974:  29 01 40 f9       ldr             x9, [x9]
0x1808b9978:  3f 01 08 eb       cmp             x9, x8
0x1808b997c:  81 00 00 54       b.ne            #0x1808b998c
0x1808b9980:  fd 7b 41 a9       ldp             x29, x30, [sp, #0x10]
0x1808b9984:  ff 83 00 91       add             sp, sp, #0x20
0x1808b9988:  ff 0f 5f d6       retab
0x1808b998c:  55 c1 e0 97       bl              ___stack_chk_fail
```
