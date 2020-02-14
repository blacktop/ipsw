---
title: "dyld"
date: 2020-01-26T09:17:35-05:00
draft: false
weight: 10
summary: Parse dyld_shared_cache.
---

- [**dyld extract**](#dyld-extract)
- [**dyld list**](#dyld-list)
- [**dyld symaddr**](#dyld-symaddr)
- [**dyld a2s**](#dyld-a2s)
- [**dyld sel**](#dyld-sel)
- [**dyld split**](#dyld-split)
- [**dyld webkit**](#dyld-webkit)

---

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

### **dyld list**

Similar to `otool -L dyld_shared_cache`

```bash
$ ipsw dyld list dyld_shared_cache

Header
======
Magic            = "dyld_v1  arm64e"
UUID             = 7659EEB7-96EB-38AB-A8B6-76367E2EC5E6
Platform         = iOS
Format           = 10
Max Slide        = 0x43704000

Local Symbols (nlist array):     57MB,  offset:  0x4F71EAA0 -> 0x530FFCB0
Local Symbols (string pool):    195MB,  offset:  0x530FFCB0 -> 0x5F4ACCED
Code Signature:                   2MB,  offset:  0x5F4B0000 -> 0x5F7AC000
ImagesText Info (1819 entries):  56KB,  offset:  0x00000198 -> 0x0000E4F8
Slide Info (v3):                 96KB,  offset:  0x48108000 -> 0x48120000
Branch Pool:                      0MB,  offset:  0x00000000 -> 0x00000000
Accelerate Tab:                 304KB,  address: 0x1D2F64000 -> 0x1D2FB0000
Dylib Image Groups:             271KB,  address: 0x1D304296C -> 0x1D30868A8
Other Image Groups:               0KB,  address: 0x00000000 -> 0x00000000
Closures:                         5MB,  address: 0x1D3148000 -> 0x1D37069F0
Closures Trie:                   47KB,  address: 0x1D37069F0 -> 0x1D3712760
Shared Region:                    4GB,  address: 0x180000000 -> 0x280000000

Mappings
========
|    SEG     | INITPROT | MAXPROT |  SIZE  |        ADDRESS         |     FILE OFFSET      |
|------------|----------|---------|--------|------------------------|----------------------|
| __TEXT     | r-x      | r-x     | 968 MB | 180000000 -> 1BC8FC000 | 00000000 -> 3C8FC000 |
| __DATA     | rw-      | rw-     | 184 MB | 1BE8FC000 -> 1CA108000 | 3C8FC000 -> 48108000 |
| __LINKEDIT | r--      | r--     | 118 MB | 1CC108000 -> 1D3714000 | 48108000 -> 4F714000 |

Images
======
   1:	0x18003C000	/usr/lib/system/libsystem_trace.dylib	(1147.60.3)
   2:	0x180053000	/usr/lib/system/libxpc.dylib	(1738.62.1)
   3:	0x180087000	/usr/lib/system/libsystem_blocks.dylib	(73.0.0)
   4:	0x180088000	/usr/lib/system/libsystem_c.dylib	(1353.60.8)
   5:	0x180107000	/usr/lib/system/libdispatch.dylib	(1173.60.1)
   6:	0x180144000	/usr/lib/system/libsystem_malloc.dylib	(283.60.1)
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

This is also create a cached version of the lookup hash table to the next time you lookup it will be much faster

```bash
$ time dist/ipsw_darwin_amd64/ipsw dyld a2s dyld_shared_cache 0x190a7221c
   • parsing public symbols...
   • parsing private symbols...
0x190a7221c: _xmlCtxtGetLastError
ipsw dyld a2s dyld_shared_cache 0x190a7221c  61.59s user 9.80s system 233% cpu "30.545 total"
```

```bash
$ time ipsw dyld a2s dyld_shared_cache 0x190a7221c
0x190a7221c: _xmlCtxtGetLastError
dist/ipsw_darwin_amd64/ipsw dyld a2s dyld_shared_cache 0x190a7221c  2.12s user 0.51s system 109% cpu "2.407 total"
```

### **dyld sel**

Get ObjC selector _(unslid)_ address

```bash
$ ipsw dyld sel dyld_shared_cache release

0x1b92c85a8: release
```

Or get all the selectors for an image

```bash
$ ipsw dyld sel --image CoreFoundation dyld_shared_cache

Objective-C Selectors:
/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
    0x1b92c88c8: exceptionWithName:reason:userInfo:
    0x1b92c878d: mutableCopyWithZone:
    0x1b92c877f: copyWithZone:
    0x1b92c88eb: initWithSet:copyItems:
    0x1b92c8820: doesNotRecognizeSelector:
    0x1b92c8902: initWithObjects:count:
    0x1b92c8919: initWithCapacity:
    0x1b92c8418: dealloc
<SNIP>
```

Get all teh selectors!!

```bash
$ ipsw dyld sel dyld_shared_cache
```

**NOTE:** This doesn't include `headers`, `class names` or `protocols` yet.

### **dyld split**

_(only on macOS)_

Split up a _dyld_shared_cache_

```bash
$ ipsw dyld split dyld_shared_cache
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
$ ipsw dyld webkit dyld_shared_cache
   • WebKit Version: 607.2.6.0.1
```
