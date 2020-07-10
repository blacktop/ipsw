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

### **macho --sig**

Similar to `jtool --sig`

```bash
$ ipsw macho /System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore --sig

Code Signature
==============
Code Directory (167849 bytes)
        Version:     Scatter
        Flags:       None
        CodeLimit:   0x14772b0
        Identifier:  com.apple.JavaScriptCore (@0x30)
        # of hashes: 5240 code (4096 pages) + 3 special
        Hashes @169 size: 32 Type: Sha256
Requirement Set (72 bytes) with 1 requirement
        Designated Requirement (@20, 72 bytes): identifier "com.apple.JavaScriptCore" AND anchor apple
```

### **macho --ent**

Similar to `jtool --ent`

```bash
$ ipsw macho /usr/libexec/amfid --ent

Entitlements
============
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
