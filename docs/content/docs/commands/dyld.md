---
title: "dyld"
date: 2020-01-26T09:17:35-05:00
draft: false
weight: 11
summary: Parse dyld_shared_cache.
---

- [**dyld --help**](#dyld---help)
- [**dyld info**](#dyld-info)
- [**dyld image**](#dyld-image)
- [**dyld extract**](#dyld-extract)
- [**dyld macho**](#dyld-macho)
- [**dyld symaddr**](#dyld-symaddr)
- [**dyld a2s**](#dyld-a2s)
- [**dyld a2f**](#dyld-a2f)
- [**dyld objc**](#dyld-objc)
  - [**dyld objc class**](#dyld-objc-class)
  - [**dyld objc proto**](#dyld-objc-proto)
  - [**dyld objc sel**](#dyld-objc-sel)
- [**dyld split**](#dyld-split)
- [**dyld webkit**](#dyld-webkit)
- [**dyld patches**](#dyld-patches)
- [**dyld slide**](#dyld-slide)
- [**dyld a2o**](#dyld-a2o)
- [**dyld o2a**](#dyld-o2a)
- [**dyld disass**](#dyld-disass)
- [**dyld imports**](#dyld-imports)
- [**dyld xref**](#dyld-xref)
- [**dyld tbd**](#dyld-tbd)
- [**dyld dump**](#dyld-dump)

---

### **dyld --help**

Help for dyld cmd

```bash
❯ ipsw dyld --help

Parse dyld_shared_cache

Usage:
  ipsw dyld [flags]
  ipsw dyld [command]

Available Commands:
  a2o         Convert dyld_shared_cache address to offset
  a2s         Lookup symbol at unslid address
  disass      Disassemble dyld_shared_cache symbol/vaddr in an image
  extract     Extract dyld_shared_cache from DMG in IPSW
  imports     List all dylibs that load a given dylib
  info        Parse dyld_shared_cache
  macho       Parse a dylib file
  o2a         Convert dyld_shared_cache offset to address
  objc        Dump Objective-C Optimization Info
  patches     Dump dyld patch info
  slide       Get slide info chained pointers
  split       Extracts all the dyld_shared_cache libraries
  symaddr     Lookup or dump symbol(s)
  tbd         Generate a .tbd file for a dylib
  webkit      Get WebKit version from a dyld_shared_cache
  xref        🚧 [WIP] Find all cross references to an address

Flags:
  -h, --help   help for dyld

Global Flags:
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output

Use "ipsw dyld [command] --help" for more information about a command.
```

### **dyld info**

Similar to `jtool -h -l dyld_shared_cache`

```bash
❯ ipsw dyld info -l -s dyld_shared_cache | head -n35

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

You can also dump the `launch closures`

```bash
❯ ipsw dyld info dyld_shared_cache --closures

Prog Closure Offsets
====================
0x1f1ec10f4     /usr/sbin/wifid
0x1f1ebfe54     /usr/sbin/syslogd
0x1f1ebda8c     /usr/sbin/spindump
0x1f1ebad54     /usr/sbin/scutil
0x1f1eb8d30     /usr/sbin/pppd
0x1f1eb7de0     /usr/sbin/otctl
0x1f1eb7818     /usr/sbin/nvram
0x1f1eb6ab4     /usr/sbin/mediaserverd
0x1f1eb24b8     /usr/sbin/mDNSResponder
0x1f1eb612c     /usr/sbin/mDNSResponderHelper
0x1f1eb197c     /usr/sbin/ipconfig
0x1f1eb1240     /usr/sbin/hdik
0x1f1eb02d8     /usr/sbin/fairplayd.H2
0x1f1eaf770     /usr/sbin/ckksctl
<SNIP>
```

You can also dump the `dlopen image/bundle(s)`

```bash
❯ ipsw dyld info dyld_shared_cache --dlopen

dlopen(s) Image/Bundle IDs
==========================
5004: /usr/lib/xpc/support.bundle/support
5003: /usr/lib/libobjc-trampolines.dylib
5002: /usr/lib/libffi-trampolines.dylib
5001: /usr/lib/libCoreKE.dylib
5000: /System/Library/VoiceServices/PlugIns/Base.vsplugin/Base
4999: /System/Library/VideoProcessors/CCPortrait.bundle/CCPortrait
4998: /System/Library/UserNotifications/Bundles/com.apple.tailspin.notifications.bundle/com.apple.tailspin.notifications
4997: /System/Library/UserNotifications/Bundles/com.apple.studentd.notifications.bundle/com.apple.studentd.notifications
4996: /System/Library/UserNotifications/Bundles/com.apple.reminders.bundle/com.apple.reminders
4995: /System/Library/UserNotifications/Bundles/com.apple.iCloud.FollowUp.bundle/com.apple.iCloud.FollowUp
4994: /System/Library/UserNotifications/Bundles/com.apple.donotdisturb.bundle/com.apple.donotdisturb
<SNIP>
```

### **dyld image**

To dump info from `dylibsImageArray`, `otherImageArray` or `progClosures`

```bash
❯ ipsw dyld image dyld_shared_cache_arm64 CoreFoundation -V
```

```
ID:                4
Name:              /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
Flags:             objc|plus_loads|dylib|in_cache
UUID:              5BBDEA97-01D2-30D8-8123-43118E96A409
Cache Segments:
	offset: 0x00354000, size: 0x003ad000, perms: r-x
	offset: 0x53130af0, size: 0x0021c370, perms: rw-
	offset: 0x5334ce60, size: 0x00008530, perms: rw-
	offset: 0x529ea080, size: 0x00007d88, perms: rw-
	offset: 0x65d94000, size: 0x00093000, perms: r--
	offset: 0x661a4000, size: 0x001a8000, perms: r--

Dependents:
	reExport) /usr/lib/libobjc.dylib
	regular ) /usr/lib/libicucore.dylib
	regular ) /usr/lib/librpcsvc.dylib

Init Order:
	/usr/lib/system/libsystem_blocks.dylib
	/usr/lib/system/libdispatch.dylib
	/usr/lib/system/libxpc.dylib
	/usr/lib/system/libsystem_trace.dylib
	/usr/lib/librpcsvc.dylib
	/usr/lib/libc++.dylib
	/usr/lib/libobjc.dylib
	/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation

Initializers:
	0x9de90

DOF Offsets:
	0x3a63a0
	0x3a6d04
```

> **NOTE:** This currently doesn't _yet_ work on macOS12+/iOS15+ caches

### **dyld extract**

Extract _dyld_shared_cache_ from a previously downloaded _ipsw_

- `macOS`

```bash
❯ ipsw dyld extract iPhone11,2_12.0_16A366_Restore.ipsw
   • Extracting dyld_shared_cache from IPSW
   • Mounting DMG
   • Extracting System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e to dyld_shared_cache
   • Unmounting DMG
```

- `docker`

```bash
❯ docker run --init -it --rm \
             --device /dev/fuse \
             --cap-add=SYS_ADMIN \
             -v `pwd` :/data \
             blacktop/ipsw -V dyld extract iPhone11_2_12.4.1_16G102_Restore.ipsw
```

### **dyld macho**

Parse a cached `dylib` MachO file

```bash
❯ ipsw dyld macho dyld_shared_cache JavaScriptCore --loads --objc

Magic         = 64-bit MachO
Type          = Dylib
CPU           = AARCH64, ARM64e caps: PAC00
Commands      = 49 (Size: 6680)
Flags         = NoUndefs, DyldLink, TwoLevel, NoReexportedDylibs, AppExtensionSafe, NlistOutofsyncWithDyldinfo, DylibInCache
000: LC_SEGMENT_64 sz=0x0027d000 off=0x390d8000-0x39355000 addr=0x1b90d8000-0x1b9355000 r-x/r-x   __TEXT
        sz=0x0022e8f4 off=0x390da674-0x39308f68 addr=0x1b90da674-0x1b9308f68            __TEXT.__text                   PureInstructions|SomeInstructions
        sz=0x00001af0 off=0x39308f68-0x3930aa58 addr=0x1b9308f68-0x1b930aa58            __TEXT.__auth_stubs             PureInstructions|SomeInstructions (SymbolStubs)
        sz=0x00004524 off=0x3930aa58-0x3930ef7c addr=0x1b930aa58-0x1b930ef7c            __TEXT.__objc_methlist
<SNIP>
```

```m
<SNIP>
0x001e39fc000 JSContext : NSObject {
  // instance variables
  +0x08 @"JSVirtualMachine" m_virtualMachine (0x8)
  +0x10 ^{OpaqueJSContext=} m_context (0x8)
  +0x18 {Strong<JSC::JSObject, JSC::ShouldStrongDestructorGrabLock::No>="m_slot"^{JSValue}} m_exception (0x8)
  +0x20 {WeakObjCPtr<id<JSModuleLoaderDelegate> >="m_weakReference"@} m_moduleLoaderDelegate (0x8)
  +0x28 @? _exceptionHandler (0x8)
}

 @property (T@"JSValue",R) globalObject
 @property (T@"JSValue",&) exception
 @property (T@?,C,V_exceptionHandler) exceptionHandler
 @property (T@"JSVirtualMachine",R) virtualMachine
 @property (T@"NSString",C) name

  // class methods
  0x0018a04680c +[JSContext currentContext]
  0x0018a046854 +[JSContext currentThis]
  0x0018a0468e8 +[JSContext currentCallee]
  0x00189e1b8d4 +[JSContext currentArguments]
  0x00189e1b4f8 +[JSContext contextWithJSGlobalContextRef:]

  // instance methods
  0x0018a046afc -[JSContext _setRemoteInspectionEnabled:]
  0x0018a046b1c -[JSContext _debuggerRunLoop]
  0x00189e19ce4 -[JSContext wrapperForJSObject:]
  0x0018a046b08 -[JSContext _includesNativeCallStackWhenReportingExceptions]
  0x00189e1c908 -[JSContext exception]
  0x00189e1ba58 -[JSContext objectForKeyedSubscript:]
  0x00189e19294 -[JSContext evaluateScript:withSourceURL:]
  0x00189e1b588 -[JSContext globalObject]
  0x0018a046b44 -[JSContext exceptionHandler]
  0x0018a0469dc -[JSContext setName:]
  0x00189e1bb28 -[JSContext setException:]
  0x00189e19eb4 -[JSContext wrapperForObjCObject:]
  0x0018a046984 -[JSContext virtualMachine]
  0x0018a046470 -[JSContext dependencyIdentifiersForModuleJSScript:]
  0x0018a046b30 -[JSContext moduleLoaderDelegate]
  0x0018a046b50 -[JSContext setExceptionHandler:]
  0x0018a046cf4 -[JSContext valueFromNotifyException:]
  0x00189e1c940 -[JSContext setObject:forKeyedSubscript:]
  0x00189e19b48 -[JSContext dealloc]
  0x0018a046b10 -[JSContext _setIncludesNativeCallStackWhenReportingExceptions:]
  0x0018a046b38 -[JSContext setModuleLoaderDelegate:]
  0x00189e19a98 -[JSContext initWithVirtualMachine:]
  0x0018a046d44 -[JSContext boolFromNotifyException:]
  0x0018a046bb0 -[JSContext initWithGlobalContextRef:]
  0x0018a04698c -[JSContext name]
  0x0018a046d68 -[JSContext wrapperMap]
  0x00189e1c298 -[JSContext beginCallbackWithData:calleeValue:thisValue:argumentCount:arguments:]
  0x00189e1c208 -[JSContext ensureWrapperMap]
  0x0018a046c78 -[JSContext notifyException:]
  0x00189e1ba44 -[JSContext evaluateScript:]
  0x00189e19c88 -[JSContext init]
  0x00189e1c900 -[JSContext .cxx_construct]
  0x0018a0461e8 -[JSContext evaluateJSScript:]
  0x0018a046b24 -[JSContext _setDebuggerRunLoop:]
  0x0018a046b58 -[JSContext .cxx_destruct]
  0x0018a04679c -[JSContext _setITMLDebuggableType]
  0x00189e1ba30 -[JSContext JSGlobalContextRef]
  0x00189e1baa0 -[JSContext endCallbackWithData:]
  0x0018a046af4 -[JSContext _remoteInspectionEnabled]
<SNIP>
```

> **NOTE:** Make the output look amazing by piping to `bat -l m --tabs 0 -p --theme Nord --wrap=never --pager "less -S"`

### **dyld symaddr**

Find all instances of a symbol's _(unslid)_ addresses in shared cache

```bash
❯ ipsw dyld symaddr dyld_shared_cache <SYMBOL_NAME>
```

Speed it up by supplying the dylib name

```bash
❯ ipsw dyld symaddr --image JavaScriptCore dyld_shared_cache <SYMBOL_NAME>
```

**NOTE:** you don't have to supply the full image path

Dump ALL teh symbolz!!!

```bash
❯ ipsw dyld symaddr dyld_shared_cache
```

Read in a JSON symbol lookup file

```bash
❯ jq . sym_lookup.json
[
  {
    "name": "__platform_memmove",
    "image": "libsystem_platform.dylib"
  },
  {
    "name": "_memcpy",
    "image": "libsystem_c.dylib"
  }
]
```

```bash
❯ ipsw dyld symaddr dyld_shared_cache --in sym_lookup.json | jq .
[
  {
    "name": "__platform_memmove",
    "image": "/usr/lib/system/libsystem_platform.dylib",
    "address": 8351373904
  },
  {
    "name": "_memcpy",
    "image": "/usr/lib/system/libsystem_c.dylib",
    "address": 8351373904
  }
]
```

### **dyld a2s**

Lookup what symbol is at a given _unslid_ or _slid_ address _(in hex)_

```bash
❯ ipsw dyld a2s dyld_shared_cache_arm64e --slide 0x27010000 0x00000001bc39e1e0

   • Address location          dylib=/usr/lib/libobjc.A.dylib section=__TEXT.__text

0x19538e1e0: _objc_msgSend + 32
```

> **NOTE:** This will also create a cached version of the lookup hash table (.a2s) so the next time you lookup it will be much faster

```bash
❯ time ipsw dyld a2s dyld_shared_cache 0x190a7221c
   • parsing public symbols...
   • parsing private symbols...
0x190a7221c: _xmlCtxtGetLastError
61.59s user 9.80s system 233% cpu "30.545 total"
```

```bash
❯ time ipsw dyld a2s dyld_shared_cache 0x190a7221c
0x190a7221c: _xmlCtxtGetLastError
2.12s user 0.51s system 109% cpu "2.407 total"
```

### **dyld a2f**

Lookup what function _(if any)_ contains a given _unslid_ or _slid_ address

```bash
❯ ipsw dyld a2f dyld_shared_cache_arm64e 0x1800980ac

0x1800980ac: _dlsym (start: 0x1800980ac, end: 0x1800980e0)
```

It can also take a file of pointers _(one per line)_ as input _(and will output results as JSON)_

```bash
❯ ipsw dyld a2f dyld_shared_cache_arm64e --in ptrs.txt \
   | jq '.[] | select(.name != null) | select(.name | contains("dlsym"))'
```

```json
{
  "addr": 6443073708,
  "start": 6443073708,
  "end": 6443073760,
  "size": 52,
  "name": "_dlsym",
  "image": "libdyld.dylib"
}
```

### **dyld objc**

#### Dump ObjC addresses

Dump all the classes

```bash
❯ ipsw dyld objc --class dyld_shared_cache
```

Dump all the protocols

```bash
❯ ipsw dyld objc --proto dyld_shared_cache
```

Dump all the selectors

```bash
❯ ipsw dyld objc --sel dyld_shared_cache
```

Dump all the imp-caches

```bash
❯ ipsw dyld objc --imp-cache dyld_shared_cache
```

### **dyld objc class**

Lookup a class's address

```bash
❯ ipsw dyld objc class dyld_shared_cache release

0x1b92c85a8: release
```

Or get all the classes for an image

```bash
❯ ipsw dyld objc class --image libobjc.A.dylib dyld_shared_cache
```

### **dyld objc proto**

Lookup a protocol's address

```bash
❯ ipsw dyld objc proto dyld_shared_cache release

0x1b92c85a8: release
```

### **dyld objc sel**

Lookup a selector's address

```bash
❯ ipsw dyld objc sel dyld_shared_cache release

0x1b92c85a8: release
```

Or get all the selectors for an image

```bash
❯ ipsw dyld objc sel --image libobjc.A.dylib iPhone12,1_N104AP_18A5319i/dyld_shared_cache

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

> **NOTE:** Only works on macOS and requires XCode to be installed to the Applications folder

Split up a _dyld_shared_cache_

```bash
❯ ipsw dyld split dyld_shared_cache .
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
❯ ipsw dyld webkit --rev dyld_shared_cache
   • WebKit Version: 609.1.17.0.1 (svn rev 256416)
```

### **dyld patches**

List dyld patch info

```bash
❯ ipsw dyld patches dyld_shared_cache | grep entries
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
❯ ipsw dyld patches dyld_shared_cache -i libdyld.dylib
0x0028074C (63 patches)  _dlclose
0x00280820 (399 patches) _dlopen
```

```bash
❯ ipsw dyld patches dyld_shared_cache -i libdyld.dylib -s _dlopen | head
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

### **dyld slide**

Dump _dyld_shared_cache_ slide info

```bash
❯ ipsw dyld slide dyld_shared_cache_arm64e

slide info version = 3
page_size          = 4096
page_starts_count  = 11956
auth_value_add     = 0x0000000180000000
page[    0]: start=0x0000
    [    0 + 0x0000] (0x1d1e48000 @ offset 0x4fe48000 => 0x1d70dabb8) value: 0x1d70dabb8, next: 01, sym: __DefaultRuneLocale
    [    0 + 0x0008] (0x1d1e48008 @ offset 0x4fe48008 => 0x2028f50e0) value: 0x2028f50e0, next: 01, sym: _OBJC_CLASS_$___NSStackBlock__
    [    0 + 0x0018] (0x1d1e48010 @ offset 0x4fe48010 => 0x1d9a3dc60) value: 0x1d9a3dc60, next: 01, sym: ___stack_chk_guard
    [    0 + 0x0030] (0x1d1e48018 @ offset 0x4fe48018 => 0x1d70da940) value: 0x1d70da940, next: 01, sym: ___stderrp
    [    0 + 0x0050] (0x1d1e48020 @ offset 0x4fe48020 => 0x1db4ecc20) value: 0x1db4ecc20, next: 01, sym: __dispatch_source_type_mach_recv
    [    0 + 0x0078] (0x1d1e48028 @ offset 0x4fe48028 => 0x191eb91dc) value: 0x191eb91dc, next: 01, sym: _free
    [    0 + 0x00A8] (0x1d1e48030 @ offset 0x4fe48030 => 0x1d9a3c02c) value: 0x1d9a3c02c, next: 01, sym: _mach_task_self_
    [    0 + 0x00E0] (0x1d1e48038 @ offset 0x4fe48038 => 0x1d9a3c048) value: 0x1d9a3c048, next: 01, sym: _vm_page_size
    [    0 + 0x0120] (0x1d1e48040 @ offset 0x4fe48040 => 0x1800a087c) value: 0x1800a087c, next: 01, sym: ?
    [    0 + 0x0168] (0x1d1e48048 @ offset 0x4fe48048 => 0x1800a0855) value: 0x1800a0855, next: 03, sym: ?
    [    0 + 0x01C8] (0x1d1e48060 @ offset 0x4fe48060 => 0x1800a0958) value: 0x1800a0958, next: 04, sym: ?
    [    0 + 0x0248] (0x1d1e48080 @ offset 0x4fe48080 => 0x1800a0958) value: 0x1800a0958, next: 04, sym: ?
    [    0 + 0x02E8] (0x1d1e480a0 @ offset 0x4fe480a0 => 0x1800a0958) value: 0x1800a0958, next: 04, sym: ?
<SNIP>
```

Dump slide info as JSON

```bash
❯ ipsw dyld slide dyld_shared_cache_arm64e --json \
   | jq '.[] | select(.pointer.authenticated == true and .pointer.key == "DA")'
```

```json
{
  "cache_file_offset": 1446288864,
  "cache_vm_address": 7955848672,
  "target": 7955848672,
  "pointer": {
    "value": 1524890997136864,
    "next": 1,
    "diversity": 27361,
    "addr_div": true,
    "key": "DA",
    "authenticated": true
  }
}
<SNIP>
```

### **dyld a2o**

Convert _dyld_shared_cache_ address to offset

```bash
❯ ipsw dyld a2o dyld_shared_cache 1D7B18000

0x053b18000
```

### **dyld o2a**

Convert _dyld_shared_cache_ offset to address

```bash
❯ ipsw dyld a2o dyld_shared_cache 0x4C6C0000

0x1ce6c0000
```

### **dyld disass**

Disassemble a function in the _dyld_shared_cache_

```bash
❯ ipsw dyld disass dyld_shared_cache_arm64e --symbol _NSLog
   • Found dyld_shared_cache companion symbol map file...
   • Locating symbol: _NSLog
   • Found symbol              dylib=/System/Library/Frameworks/Foundation.framework/Foundation
   • Parsing ObjC runtime structures...
```

> **NOTE:** You can speed up symbol lookups by supplying the `--image` flag or you can use the `--vaddr` flag

```s
_NSLog:
0x181bac214:  7f 23 03 d5	pacibsp
0x181bac218:  ff 83 00 d1	sub	sp, sp, #0x20
0x181bac21c:  fd 7b 01 a9	stp	x29, x30, [sp, #0x10]
0x181bac220:  fd 43 00 91	add	x29, sp, #0x10
0x181bac224:  28 e9 2b f0	adrp	x8, 0x1d98d3000
0x181bac228:  08 45 41 f9	ldr	x8, [x8, #0x288] ; __got.___stack_chk_guard
0x181bac22c:  08 01 40 f9	ldr	x8, [x8]
0x181bac230:  e8 07 00 f9	str	x8, [sp, #0x8]
0x181bac234:  a8 43 00 91	add	x8, x29, #0x10
0x181bac238:  e8 03 00 f9	str	x8, [sp]
0x181bac23c:  e2 03 1e aa	mov	x2, x30
0x181bac240:  e2 43 c1 da	xpaci	x2
0x181bac244:  a1 43 00 91	add	x1, x29, #0x10
0x181bac248:  2a 22 00 94	bl	__NSLogv
0x181bac24c:  e8 07 40 f9	ldr	x8, [sp, #0x8]
0x181bac250:  29 e9 2b f0	adrp	x9, 0x1d98d3000
0x181bac254:  29 45 41 f9	ldr	x9, [x9, #0x288] ; __got.___stack_chk_guard
0x181bac258:  29 01 40 f9	ldr	x9, [x9]
0x181bac25c:  3f 01 08 eb	cmp	x9, x8
0x181bac260:  81 00 00 54	b.ne	loc_181bac270 ; ⤵ 0x10
0x181bac264:  fd 7b 41 a9	ldp	x29, x30, [sp, #0x10]
0x181bac268:  ff 83 00 91	add	sp, sp, #0x20
0x181bac26c:  ff 0f 5f d6	retab
0x181bac270:  ; loc_181bac270
0x181bac270:  3e 85 93 97	bl	j____stack_chk_fail
```

> **NOTE:** Make the output look amazing by adding the `--color` flag 🌈

### **dyld imports**

List all dylibs that import/load a given dylib in the _dyld_shared_cache_

```bash
❯ ipsw dyld imports dyld_shared_cache JavaScriptCore

JavaScriptCore Imported By:
===========================
/System/Library/Frameworks/WebKit.framework/WebKit
/System/Library/PrivateFrameworks/WebCore.framework/WebCore
/System/Library/PrivateFrameworks/WebBookmarks.framework/WebBookmarks
/System/Library/PrivateFrameworks/SafariShared.framework/SafariShared
/System/Library/PrivateFrameworks/JetEngine.framework/JetEngine
/System/Library/Frameworks/SafariServices.framework/SafariServices
/System/Library/PrivateFrameworks/WebKitLegacy.framework/WebKitLegacy
/System/Library/PrivateFrameworks/SafariSharedUI.framework/SafariSharedUI
/System/Library/PrivateFrameworks/VideosUI.framework/VideosUI
/System/Library/PrivateFrameworks/StoreKitUI.framework/StoreKitUI
/System/Library/PrivateFrameworks/iTunesStoreUI.framework/iTunesStoreUI
/System/Library/PrivateFrameworks/ITMLKit.framework/ITMLKit
/System/Library/PrivateFrameworks/AppStoreKit.framework/AppStoreKit
/System/Library/PrivateFrameworks/WorkflowKit.framework/WorkflowKit
/System/Library/PreferenceBundles/MobileSafariSettings.bundle/MobileSafariSettings
/System/Library/PrivateFrameworks/ActionKit.framework/ActionKit
/System/Library/PrivateFrameworks/Cards.framework/Cards
/System/Library/PrivateFrameworks/CommunicationsSetupUI.framework/CommunicationsSetupUI
/System/Library/PrivateFrameworks/CoreChart.framework/CoreChart
/System/Library/PrivateFrameworks/JITAppKit.framework/JITAppKit
/System/Library/PrivateFrameworks/MailWebProcessSupport.framework/MailWebProcessSupport
/System/Library/PrivateFrameworks/MetricsKit.framework/MetricsKit
/System/Library/PrivateFrameworks/RemoteUI.framework/RemoteUI
/System/Library/PrivateFrameworks/SeymourServices.framework/SeymourServices
/System/Library/PrivateFrameworks/SlideshowKit.framework/Frameworks/OpusKit.framework/OpusKit
/System/Library/PrivateFrameworks/TVMLKit.framework/TVMLKit
/System/Library/PrivateFrameworks/TelephonyPreferences.framework/TelephonyPreferences
/System/Library/PrivateFrameworks/TouchML.framework/TouchML
/System/Library/PrivateFrameworks/VideoSubscriberAccountUI.framework/VideoSubscriberAccountUI
/System/Library/PrivateFrameworks/WebApp.framework/WebApp
/System/Library/PrivateFrameworks/WebInspector.framework/WebInspector
/System/Library/PrivateFrameworks/WebUI.framework/WebUI
/System/Library/PrivateFrameworks/WorkflowEditor.framework/WorkflowEditor
```

### **dyld xref**

List all the cross-references in the _dyld_shared_cache_ for a given virtual address

```bash
ipsw dyld symaddr dyld_shared_cache_arm64e _NSLog
0x1817e73e4: (Regular) _NSLog   /System/Library/Frameworks/Foundation.framework/Foundation
```

```bash
❯ ipsw dyld xref dyld_shared_cache 0x1817e73e4
   • Address location          dylib=/System/Library/Frameworks/Foundation.framework/Foundation sym=_NSLog

XREFS (304)
===========
0x181828034: -[__NSConcreteURLComponents percentEncodedHost] + 96
0x1817ca15c: _NSCountMapTable + 48
0x1817fc33c: -[NSItemProvider loadDataRepresentationForTypeIdentifier:completionHandler:] + 264
0x18181a8fc: +[NSString(NSStringOtherEncodings) localizedNameOfStringEncoding:] + 84
0x181760ef0: -[NSCharacterSet mutableCopyWithZone:] + 60
0x181790fcc: _NSFreeHashTable + 48
0x181791244: _NSHashInsertKnownAbsent + 52
0x1817c9b70: _NSEnumerateMapTable + 56
<SNIP>
```

### **dyld tbd**

Generate a `.tbd` file for a dylib

```bash
❯ ipsw dyld tbd dyld_shared_cache CoreSymbolication
   • Created CoreSymbolication.tbd
```

```bash
❯ cat CoreSymbolication.tbd
---
archs:           [ arm64e ]
platform:        ios
install-name:    /System/Library/PrivateFrameworks/CoreSymbolication.framework/CoreSymbolication
current-version: 64544.69.1.0.0
exports:
  - archs:           [ arm64e ]
    symbols:         [ _unmap_node, _thread_name_for_thread_port, <SNIP> ]
...
```

### **dyld dump**

First print the MachO header for `CoreData` in a cache

```bash
❯ ipsw dyld macho dyld_shared_cache_arm64e CoreData | grep "__DATA_CONST.__got"
        sz="0x000002d8" off=0x502c2428-0x502c2700 addr="0x1d22c2428"-0x1d22c2700            __DATA_CONST.__got               (NonLazySymbolPointers)
```

Hexdump the section `__DATA_CONST.__got`

```bash
❯ ipsw dyld dump dyld_shared_cache_arm64e 0x1d22c2428 --size 728 # 0x2d8 in decimal

00000000  00 46 a8 d9 01 00 08 00  90 ba a8 d9 01 00 08 00  |.F..............|
00000010  52 3b d8 d6 01 00 08 00  20 ba a8 d9 01 00 08 00  |R;...... .......|
00000020  18 bc a8 d9 01 00 08 00  b0 bc a8 d9 01 00 08 00  |................|
00000030  b8 bc a8 d9 01 00 08 00  c0 bc a8 d9 01 00 08 00  |................|
00000040  a0 bc a8 d9 01 00 08 00  a8 bc a8 d9 01 00 08 00  |................|
00000050  e8 bb a8 d9 01 00 08 00  88 bc a8 d9 01 00 08 00  |................|
00000060  b0 bb a8 d9 01 00 08 00  b0 3d a8 d9 01 00 08 00  |.........=......|
00000070  30 bb a8 d9 01 00 08 00  c8 3d a8 d9 01 00 08 00  |0........=......|
<SNIP>
```

Or dump the section as a list of pointers

```bash
❯ ipsw dyld dump dyld_shared_cache_arm64e 0x1d22c2428 --size 728 --addr

0x1d9a84600
0x1d9a8ba90
0x1d6d83b52
0x1d9a8ba20
0x1d9a8bc18
0x1d9a8bcb0
0x1d9a8bcb8
0x1d9a8bcc0
0x1d9a8bca0
0x1d9a8bca8
<SNIP>
```

Lookup those pointers in the cache

```bash
❯ ipsw dyld dump dyld_shared_cache_arm64e 0x1d22c2428 --size 728 --addr | xargs -I {} /bin/zsh -c 'ipsw dyld a2s dyld_shared_cache_arm64e {}'

   • Address location          dylib=/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation section=__DATA_CONST.__const
0x1d9a84600: _NSCalendarIdentifierGregorian

   • Address location          dylib=/System/Library/Frameworks/Foundation.framework/Foundation section=__DATA_CONST.__const
0x1d9a8ba90: _NSCocoaErrorDomain

   • Address location          dylib=/System/Library/Frameworks/Foundation.framework/Foundation section=__DATA.__common
0x1d6d83b52: _NSDeallocateZombies

   • Address location          dylib=/System/Library/Frameworks/Foundation.framework/Foundation section=__DATA_CONST.__const
0x1d9a8ba20: _NSFilePathErrorKey

<SNIP>
```

Or write to a file for later post-processing

```bash
❯ ipsw dyld dump dyld_shared_cache_arm64e 0x1d22c2428 --size 728 --output ./data.bin
   • Wrote data to file ./data.bin
```

```bash
❯ hexdump -C data.bin
00000000  00 46 a8 d9 01 00 08 00  90 ba a8 d9 01 00 08 00  |.F..............|
00000010  52 3b d8 d6 01 00 08 00  20 ba a8 d9 01 00 08 00  |R;...... .......|
00000020  18 bc a8 d9 01 00 08 00  b0 bc a8 d9 01 00 08 00  |................|
00000030  b8 bc a8 d9 01 00 08 00  c0 bc a8 d9 01 00 08 00  |................|
00000040  a0 bc a8 d9 01 00 08 00  a8 bc a8 d9 01 00 08 00  |................|
00000050  e8 bb a8 d9 01 00 08 00  88 bc a8 d9 01 00 08 00  |................|
00000060  b0 bb a8 d9 01 00 08 00  b0 3d a8 d9 01 00 08 00  |.........=......|
00000070  30 bb a8 d9 01 00 08 00  c8 3d a8 d9 01 00 08 00  |0........=......|
00000080  c0 3d a8 d9 01 00 08 00  68 be a8 d9 01 00 08 00  |.=......h.......|
00000090  70 be a8 d9 01 00 08 00  78 be a8 d9 01 00 08 00  |p.......x.......|
<SNIP>
```
