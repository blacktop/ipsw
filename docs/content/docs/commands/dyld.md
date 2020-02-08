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
Magic               = dyld_v1  arm64e
MappingOffset       = 00000138
MappingCount        = 3
ImagesOffset        = 00000198
ImagesCount         = 1819
DyldBaseAddress     = 00000000
CodeSignatureOffset = 5F4B0000
CodeSignatureSize   = 002FC000
SlideInfoOffset     = 48108000
SlideInfoSize       = 00018000
LocalSymbolsOffset  = 4F714000
LocalSymbolsSize    = 0FD9C000
UUID                = 7659EEB7-96EB-38AB-A8B6-76367E2EC5E6
Platform            = iOS
Format              = 10
Slide Info:      96KB,  file offset: 0x48108000 -> 0x48120000
Local Symbols:  253MB,  file offset: 0x4F714000 -> 0x5F4B0000
Accelerate Tab: 304KB,  address: 0x1D2F64000 -> 0x1D2FB0000

Mappings
========
|    SEG     | INITPROT | MAXPROT |  SIZE  |        ADDRESS         |     FILE OFFSET      |
|------------|----------|---------|--------|------------------------|----------------------|
| __TEXT     | r-x      | r-x     | 968 MB | 180000000 -> 1BC8FC000 | 00000000 -> 3C8FC000 |
| __DATA     | rw-      | rw-     | 184 MB | 1BE8FC000 -> 1CA108000 | 3C8FC000 -> 48108000 |
| __LINKEDIT | r--      | r--     | 118 MB | 1CC108000 -> 1D3714000 | 48108000 -> 4F714000 |

Images
======
1:      18003c000 /usr/lib/system/libsystem_trace.dylib
2:      180053000 /usr/lib/system/libxpc.dylib
3:      180087000 /usr/lib/system/libsystem_blocks.dylib
4:      180088000 /usr/lib/system/libsystem_c.dylib
5:      180107000 /usr/lib/system/libdispatch.dylib
6:      180144000 /usr/lib/system/libsystem_malloc.dylib
7:      180165000 /usr/lib/system/libsystem_platform.dylib
<SNIP>
```

### **dyld symaddr**

Find symbol _(unslid)_ addresses in shared cache

```bash
$ ipsw dyld symaddr dyld_shared_cache <SYMBOL_NAME>
```

Speed it up by supplying the dylib name

```bash
$ ipsw dyld symaddr --image JavaScriptCore dyld_shared_cache <SYMBOL_NAME>
```

⚠️ **NOTE:** you don't have to supply the full image path

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
