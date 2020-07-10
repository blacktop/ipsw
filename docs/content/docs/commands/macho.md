---
title: "macho"
date: 2020-01-26T09:17:20-05:00
draft: false
weight: 8
summary: Parse a MachO file
---

- [**macho -d**](#macho--d)
- [**macho -l**](#macho--l)
- [**macho --sig**](#macho---sig)
- [**macho --ent**](#macho---ent)
- [**macho --objc**](#macho---objc)

### **macho -d**

Similar to `otool -h`

```bash
$ ipsw macho JavaScriptCore

Magic         = 64-bit MachO
Type          = Dylib
CPU           = AARCH64, ARM64e (ARMv8.3) caps: PAC00
Commands      = 25 (Size: 4384)
Flags         = NoUndefs, DyldLink, TwoLevel, BindsToWeak, NoReexportedDylibs, AppExtensionSafe
```

### **macho -l**

Similar to `otool -h -l`

```bash
$ ipsw macho JavaScriptCore

Magic         = 64-bit MachO
Type          = Dylib
CPU           = AARCH64, ARM64e (ARMv8.3) caps: PAC00
Commands      = 25 (Size: 4464)
Flags         = NoUndefs, DyldLink, TwoLevel, BindsToWeak, NoReexportedDylibs, AppExtensionSafe
00: LC_SEGMENT_64 offset=0x00000000-0x00fcf000, addr=0x19152f000-0x1924fe000    __TEXT
        offset=0x00001cd0-0x00ed548c, addr=0x191530cd0-0x19240448c              __TEXT.__text           PureInstructions|SomeInstructions
        offset=0x00ed548c-0x00ed743c, addr=0x19240448c-0x19240643c              __TEXT.__auth_stubs     (SymbolStubs)   PureInstructions|SomeInstructions
        offset=0x00ed7440-0x00ed7d44, addr=0x192406440-0x192406d44              __TEXT.__objc_methlist
        offset=0x00ed7d50-0x00f2ffe0, addr=0x192406d50-0x19245efe0              __TEXT.__const
        offset=0x00f2ffe0-0x00fcba71, addr=0x19245efe0-0x1924faa71              __TEXT.__cstring        (Cstring Literals)
        offset=0x00fcba74-0x00fcd920, addr=0x1924faa74-0x1924fc920              __TEXT.__gcc_except_tab
        offset=0x00fcd920-0x00fcdf68, addr=0x1924fc920-0x1924fcf68              __TEXT.__oslogstring    (Cstring Literals)
        offset=0x00fcdf68-0x00fcee9c, addr=0x1924fcf68-0x1924fde9c              __TEXT.__unwind_info
        offset=0x00000000-0x00000000, addr=0x1924fe000-0x1924fe000              __TEXT.__objc_classname (Cstring Literals)
        offset=0x00000000-0x00000000, addr=0x1924fe000-0x1924fe000              __TEXT.__objc_methname  (Cstring Literals)
        offset=0x00000000-0x00000000, addr=0x1924fe000-0x1924fe000              __TEXT.__objc_methtype  (Cstring Literals)
01: LC_SEGMENT_64 offset=0x00fcf000-0x00fda058, addr=0x1cfda7780-0x1cfdb27d8    __DATA_CONST
        offset=0x00fcf000-0x00fcf120, addr=0x1cfda7780-0x1cfda78a0              __DATA_CONST.__got      (NonLazySymbolPointers)
        offset=0x00fcf120-0x00fd9508, addr=0x1cfda78a0-0x1cfdb1c88              __DATA_CONST.__const
        offset=0x00fd9508-0x00fd9560, addr=0x1cfdb1c88-0x1cfdb1ce0              __DATA_CONST.__objc_classlist           NoDeadStrip
        offset=0x00fd9560-0x00fd9560, addr=0x1cfdb1ce0-0x1cfdb1ce0              __DATA_CONST.__objc_catlist             NoDeadStrip
        offset=0x00fd9560-0x00fd9578, addr=0x1cfdb1ce0-0x1cfdb1cf8              __DATA_CONST.__objc_protolist
        offset=0x00fd9578-0x00fd9580, addr=0x1cfdb1cf8-0x1cfdb1d00              __DATA_CONST.__objc_imageinfo
        offset=0x00fd9580-0x00fda058, addr=0x1cfdb1d00-0x1cfdb27d8              __DATA_CONST.__objc_const
02: LC_SEGMENT_64 offset=0x00fda058-0x00fdaf70, addr=0x1d3461278-0x1d3462190    __DATA
        offset=0x00fda058-0x00fda898, addr=0x1d3461278-0x1d3461ab8              __DATA.__objc_selrefs   (Literal Pointers)      NoDeadStrip
        offset=0x00fda898-0x00fda9a0, addr=0x1d3461ab8-0x1d3461bc0              __DATA.__objc_classrefs         NoDeadStrip
        offset=0x00fda9a0-0x00fda9d8, addr=0x1d3461bc0-0x1d3461bf8              __DATA.__objc_superrefs         NoDeadStrip
        offset=0x00fda9d8-0x00fdaa58, addr=0x1d3461bf8-0x1d3461c78              __DATA.__objc_ivar
        offset=0x00fdaa58-0x00fdac70, addr=0x1d3461c78-0x1d3461e90              __DATA.__data
        offset=0x00000000-0x000001f8, addr=0x1d3461e90-0x1d3462088              __DATA.__common (Zerofill)
        offset=0x00000000-0x00000108, addr=0x1d3462088-0x1d3462190              __DATA.__bss    (Zerofill)
03: LC_SEGMENT_64 offset=0x00fdaf70-0x0100ed18, addr=0x1d82b6308-0x1d82ea0b0    __AUTH_CONST
        offset=0x00fdaf70-0x0100bf40, addr=0x1d82b6308-0x1d82e72d8              __AUTH_CONST.__const
        offset=0x0100bf40-0x0100ced8, addr=0x1d82e72d8-0x1d82e8270              __AUTH_CONST.__auth_ptr
        offset=0x0100ced8-0x0100dd38, addr=0x1d82e8270-0x1d82e90d0              __AUTH_CONST.__cfstring
        offset=0x0100dd38-0x0100dd38, addr=0x1d82e90d0-0x1d82e90d0              __AUTH_CONST.__objc_const
        offset=0x0100dd38-0x0100ed10, addr=0x1d82e90d0-0x1d82ea0a8              __AUTH_CONST.__auth_got (NonLazySymbolPointers)
        offset=0x0100ed10-0x0100ed18, addr=0x1d82ea0a8-0x1d82ea0b0              __AUTH_CONST.__got      (NonLazySymbolPointers)
04: LC_SEGMENT_64 offset=0x0100ed18-0x01020388, addr=0x1db1e4000-0x1db1f5670    __DATA_DIRTY
        offset=0x0100ed18-0x0100ef98, addr=0x1db1e4000-0x1db1e4280              __DATA_DIRTY.__objc_data
        offset=0x0100ef98-0x01013130, addr=0x1db1e4280-0x1db1e8418              __DATA_DIRTY.__data
        offset=0x00000000-0x00008668, addr=0x1db1ec000-0x1db1f4668              __DATA_DIRTY.__common   (Zerofill)
        offset=0x00000000-0x00001008, addr=0x1db1f4668-0x1db1f5670              __DATA_DIRTY.__bss      (Zerofill)
05: LC_SEGMENT_64 offset=0x01020388-0x01020480, addr=0x1dce25a40-0x1dce25b38    __AUTH
        offset=0x01020388-0x01020478, addr=0x1dce25a40-0x1dce25b30              __AUTH.__objc_data
        offset=0x01020478-0x01020480, addr=0x1dce25b30-0x1dce25b38              __AUTH.__data
06: LC_SEGMENT_64 offset=0x01020480-0x01020ab0, addr=0x1d82ea0b0-0x1d82ea6e0    __OBJC_CONST
        offset=0x01020480-0x01020ab0, addr=0x1d82ea0b0-0x1d82ea6e0              __OBJC_CONST.__objc_class_ro
07: LC_SEGMENT_64 offset=0x01020ab0-0x0138476c, addr=0x1dfb84000-0x1dfee8000    __LINKEDIT
08: LC_ID_DYLIB                 /System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore (610.1.18)
09: LC_DYLD_EXPORTS_TRIE        Count: 0
10: LC_SYMTAB                   Symbol offset=0x0102BA28, Num Syms: 30476, String offset=0x010A3B54-0x0138476C
11: LC_DYSYMTAB                 1051 Indirect symbols at offset 0x010A2AE8
12: LC_UUID                     DA451B8C-AD8B-3017-BC14-81D074636B66
13: LC_BUILD_VERSION            Platform: iOS, SDK: 14.0.0, Tool: ld (607.4.0)
14: LC_SOURCE_VERSION           7610.1.18.20.3
15: LC_LOAD_DYLIB               /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation (1742.102.0)
16: LC_LOAD_DYLIB               /System/Library/Frameworks/Foundation.framework/Foundation (1742.102.0)
17: LC_LOAD_DYLIB               /usr/lib/libicucore.A.dylib (66.0.0)
18: LC_LOAD_DYLIB               /usr/lib/libobjc.A.dylib (228.0.0)
19: LC_LOAD_DYLIB               /usr/lib/libz.1.dylib (1.2.11)
20: LC_LOAD_DYLIB               /System/Library/Frameworks/Security.framework/Security (59731.0.0)
21: LC_LOAD_DYLIB               /usr/lib/libc++.1.dylib (904.4.0)
22: LC_LOAD_DYLIB               /usr/lib/libSystem.B.dylib (1292.0.0)
23: LC_FUNCTION_STARTS          offset=0x01020ab0-0x0102ba28, size=44920, count=26030
24: LC_DATA_IN_CODE             offset=0x0102ba28-0x0102ba28, size=    0, entries=0
```

### **macho --sig**

Similar to `jtool --sig`

```bash
$ ipsw macho /System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore --sig

Code Directory (167849 bytes)
        Version:     Scatter
        Flags:       None
        CodeLimit:   0x14772b0
        Identifier:  com.apple.JavaScriptCore (@0x30)
        # of hashes: 5240 code (4096 pages) + 3 special
        Hashes @169 size: 32 Type: Sha256
Requirement Set (72 bytes) with 1 requirement
        Designated Requirement (@20, 72 bytes): identifier "com.apple.JavaScriptCore" AND anchor apple
CMS (RFC3852) signature:
        OU: Apple Certification Authority CN: Apple Code Signing Certification Authority (2011-10-24 thru 2026-10-24)
        OU: Apple Certification Authority CN: Apple Root CA                              (2006-04-25 thru 2035-02-09)
        OU: Apple Certification Authority CN: Software Signing                           (2013-04-12 thru 2021-04-12)
```

### **macho --ent**

Similar to `jtool --ent`

```bash
$ ipsw macho /usr/libexec/amfid --ent
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>com.apple.private.security.storage.SystemPolicyConfiguration</key>
        <true/>
        <key>com.apple.private.tcc.allow</key>
        <array>
                <string>kTCCServiceSystemPolicyAllFiles</string>
        </array>
        <key>com.apple.rootless.storage.SystemPolicyConfiguration</key>
        <true/>
</dict>
</plist>
```

### **macho --objc**

Similar to `objdump --macho --objc-meta-data` OR `dsdump --objc -vv`

**NOTE:** I first ran `lipo -thin x86_64 /usr/lib/libobjc.A.dylib -output ./libobjc.A.dylib`

```bash
$ ipsw macho libobjc.A.dylib --objc

Objective-C
===========
@protocol NSObject
 @property hash
 @property superclass
 @property description
 @property debugDescription

  // instance methods
 -[NSObject isEqual:]
 -[NSObject class]
 -[NSObject self]
 -[NSObject performSelector:]
 -[NSObject performSelector:withObject:]
 -[NSObject performSelector:withObject:withObject:]
 -[NSObject isProxy]
 -[NSObject isKindOfClass:]
 -[NSObject isMemberOfClass:]
 -[NSObject conformsToProtocol:]
 -[NSObject respondsToSelector:]
 -[NSObject retain]
 -[NSObject release]
 -[NSObject autorelease]
 -[NSObject retainCount]
 -[NSObject zone]
 -[NSObject hash]
 -[NSObject superclass]
 -[NSObject description]

@optional
  // instance methods
 -[NSObject debugDescription]
@end

0x00000035000 Object : <ROOT>
  // instance methods
  0x000000210b9 -[Object retain]
  0x000000210be -[Object release]
  0x000000210c3 -[Object autorelease]

0x00000035078 __IncompleteProtocol : NSObject

0x000000350c8 Protocol : NSObject
  // instance methods
  0x000000210d9 -[Protocol conformsTo:]
  0x000000210e1 -[Protocol descriptionForInstanceMethod:]
  0x00000021100 -[Protocol descriptionForClassMethod:]
  0x0000002111c -[Protocol name]
  0x0000002112d -[Protocol isEqual:]
  0x000000211c2 -[Protocol hash]

0x00000035168 __NSUnrecognizedTaggedPointer : NSObject
  // instance methods
  0x00000022d0e -[__NSUnrecognizedTaggedPointer retain]
  0x00000022d12 -[__NSUnrecognizedTaggedPointer release]
  0x00000022d13 -[__NSUnrecognizedTaggedPointer autorelease]

0x00000035118 NSObject : <ROOT>
  // instance methods
  0x0000000ac6f -[NSObject self]
  0x00000009d13 -[NSObject class]
  0x00000011301 -[NSObject superclass]
  0x0000000b258 -[NSObject isMemberOfClass:]
  0x0000000a3df -[NSObject isKindOfClass:]
  0x0000000ac75 -[NSObject respondsToSelector:]
  0x0000000b2d1 -[NSObject conformsToProtocol:]
  0x0000000a7bb -[NSObject hash]
  0x00000009cef -[NSObject isEqual:]
  0x00000012a68 -[NSObject isFault]
  0x0000001131b -[NSObject isProxy]
  0x0000000bc3e -[NSObject methodForSelector:]
  0x00000022522 -[NSObject doesNotRecognizeSelector:]
  0x0000000d6c9 -[NSObject performSelector:]
  0x0000000da2d -[NSObject performSelector:withObject:]
  0x0000000fd60 -[NSObject performSelector:withObject:withObject:]
  0x00000022568 -[NSObject methodSignatureForSelector:]
  0x0000002257a -[NSObject forwardInvocation:]
  0x0000000c955 -[NSObject forwardingTargetForSelector:]
  0x000000225b8 -[NSObject description]
  0x000000225bb -[NSObject debugDescription]
  0x00000007c98 -[NSObject retain]
  0x00000010b7d -[NSObject _tryRetain]
  0x0000000ec4b -[NSObject _isDeallocating]
  0x0000000ec23 -[NSObject allowsWeakReference]
  0x0000000ff3f -[NSObject retainWeakReference]
  0x00000009b0c -[NSObject release]
  0x00000009c61 -[NSObject autorelease]
  0x00000010a96 -[NSObject retainCount]
  0x000000095ab -[NSObject init]
  0x00000007d3f -[NSObject dealloc]
  0x000000225d4 -[NSObject finalize]
  0x0000000b2c5 -[NSObject zone]
  0x00000009cda -[NSObject copy]
  0x00000009cf9 -[NSObject mutableCopy]

0x00000035078 __IncompleteProtocol : NSObject

0x000000350c8 Protocol : NSObject
  // instance methods
  0x000000210d9 -[Protocol conformsTo:]
  0x000000210e1 -[Protocol descriptionForInstanceMethod:]
  0x00000021100 -[Protocol descriptionForClassMethod:]
  0x0000002111c -[Protocol name]
  0x0000002112d -[Protocol isEqual:]
  0x000000211c2 -[Protocol hash]

0x00000035168 __NSUnrecognizedTaggedPointer : NSObject
  // instance methods
  0x00000022d0e -[__NSUnrecognizedTaggedPointer retain]
  0x00000022d12 -[__NSUnrecognizedTaggedPointer release]
  0x00000022d13 -[__NSUnrecognizedTaggedPointer autorelease]

0x00000035118 NSObject : <ROOT>
  // instance methods
  0x0000000ac6f -[NSObject self]
  0x00000009d13 -[NSObject class]
  0x00000011301 -[NSObject superclass]
  0x0000000b258 -[NSObject isMemberOfClass:]
  0x0000000a3df -[NSObject isKindOfClass:]
  0x0000000ac75 -[NSObject respondsToSelector:]
  0x0000000b2d1 -[NSObject conformsToProtocol:]
  0x0000000a7bb -[NSObject hash]
  0x00000009cef -[NSObject isEqual:]
  0x00000012a68 -[NSObject isFault]
  0x0000001131b -[NSObject isProxy]
  0x0000000bc3e -[NSObject methodForSelector:]
  0x00000022522 -[NSObject doesNotRecognizeSelector:]
  0x0000000d6c9 -[NSObject performSelector:]
  0x0000000da2d -[NSObject performSelector:withObject:]
  0x0000000fd60 -[NSObject performSelector:withObject:withObject:]
  0x00000022568 -[NSObject methodSignatureForSelector:]
  0x0000002257a -[NSObject forwardInvocation:]
  0x0000000c955 -[NSObject forwardingTargetForSelector:]
  0x000000225b8 -[NSObject description]
  0x000000225bb -[NSObject debugDescription]
  0x00000007c98 -[NSObject retain]
  0x00000010b7d -[NSObject _tryRetain]
  0x0000000ec4b -[NSObject _isDeallocating]
  0x0000000ec23 -[NSObject allowsWeakReference]
  0x0000000ff3f -[NSObject retainWeakReference]
  0x00000009b0c -[NSObject release]
  0x00000009c61 -[NSObject autorelease]
  0x00000010a96 -[NSObject retainCount]
  0x000000095ab -[NSObject init]
  0x00000007d3f -[NSObject dealloc]
  0x000000225d4 -[NSObject finalize]
  0x0000000b2c5 -[NSObject zone]
  0x00000009cda -[NSObject copy]
  0x00000009cf9 -[NSObject mutableCopy]

@selectors
0x00000032c3a: _tryRetain
0x00000032e96: init
0x00000032c1f: allocWithZone:
0x00000032ccb: mutableCopyWithZone:
0x00000032b87: release
0x00000032c55: retainCount
0x00000032ba8: retainWeakReference
0x00000032bbc: new
0x00000032bc0: self
0x00000032c19: alloc
0x00000032c2e: autorelease
0x00000032b8f: load
0x00000032bee: resolveInstanceMethod:
0x00000032d87: description
0x00000032e9b: dealloc
0x00000032e0c: doesNotRecognizeSelector:
0x00000032b75: initialize
0x00000032bc5: class
0x00000032bcb: isKindOfClass:
0x00000032bda: respondsToSelector:
0x00000032b80: retain
0x00000032ce0: copy
0x00000032b94: allowsWeakReference
0x00000032c05: resolveClassMethod:
0x00000032c45: _isDeallocating
0x00000032eaf: selector
0x00000032cbd: copyWithZone:

@methods
0x00000032d87: description
0x00000032b94: allowsWeakReference
0x00000032bcb: isKindOfClass:
0x00000032c1f: allocWithZone:
0x00000032cb8: hash
0x00000032ccb: mutableCopyWithZone:
0x00000032b8f: load
0x00000032bbc: new
0x00000032e9b: dealloc
0x00000032eaf: selector
0x00000032eb8: finalize
0x00000032b87: release
0x00000032bee: resolveInstanceMethod:
0x00000032c19: alloc
0x00000032e0c: doesNotRecognizeSelector:
0x00000032e26: instanceMethodSignatureForSelector:
0x00000032d93: isSubclassOfClass:
0x00000032e4a: methodSignatureForSelector:
0x00000032b75: initialize
0x00000032ba8: retainWeakReference
0x00000032bc5: class
0x00000032c71: descriptionForInstanceMethod:
0x00000032d77: zone
0x00000032d7c: superclass
0x00000032df9: methodForSelector:
0x00000032e96: init
0x00000032c2e: autorelease
0x00000032c55: retainCount
0x00000032caf: isEqual:
0x00000032d07: performSelector:withObject:
0x00000032d23: performSelector:withObject:withObject:
0x00000032dba: instancesRespondToSelector:
0x00000032e66: forwardInvocation:
0x00000032bda: respondsToSelector:
0x00000032caa: name
0x00000032d63: conformsToProtocol:
0x00000032ea3: mutableCopy
0x00000032b80: retain
0x00000032c3a: _tryRetain
0x00000032cbd: copyWithZone:
0x00000032da6: isAncestorOfObject:
0x00000032dde: instanceMethodForSelector:
0x00000032bc0: self
0x00000032c45: _isDeallocating
0x00000032cf6: performSelector:
0x00000032d4a: isProxy
0x00000032dd6: isFault
0x00000032c05: resolveClassMethod:
0x00000032c65: conformsTo:
0x00000032ce0: copy
0x00000032c8f: descriptionForClassMethod:
0x00000032d52: isMemberOfClass:
0x00000032e79: forwardingTargetForSelector:
0x00000032c61: isa
0x00000032ce5: debugDescription
```
