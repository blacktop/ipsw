---
description: All the MANY ways you can parse MachO files.
---

# Parse MachO files

### **macho a2o**

Convert MachO address to offset

```bash
❯ ipsw macho a2o kernelcache 0xfffffff0070b4000
   • Offset     dec=720896 hex=0xb0000 section=__mod_init_func segment=__DATA_CONST
```

### **macho o2a**

Convert MachO offset to address

```bash
❯ ipsw macho o2a kernelcache 0x007dc000
   • Address    dec=18446744005115772928 hex=0xfffffff0077e0000 section=__data segment=__DATA
```

### **macho lipo**

Extract file from Universal/FAT MachO

```bash
❯ ipsw macho lipo debugserver

• Extracted ARM64e file as debugserver.arm64e
```

:::info note
You can supply `--arch arm64e` instead of using the arch picker UI
:::

### **macho bbl**

Create single universal/fat MachO out many MachOs

```bash
❯ ipsw macho bbl /tmp/ls.x86_64 /tmp/ls.arm64e --output /tmp/ls
```

### **macho dump**

Hexdump the section `__DATA_CONST.__mod_init_func`

```bash
❯ ipsw dyld dump kernelcache --section __DATA_CONST.__mod_init_func --size 656 # 0x290 in decimal

00000000  34 ba 69 07 f0 ff ff ff  0c c2 69 07 f0 ff ff ff  |4.i.......i.....|
00000010  98 e5 69 07 f0 ff ff ff  18 fc 69 07 f0 ff ff ff  |..i.......i.....|
00000020  b8 05 6a 07 f0 ff ff ff  b0 0d 6a 07 f0 ff ff ff  |..j.......j.....|
00000030  08 19 6a 07 f0 ff ff ff  b4 2c 6a 07 f0 ff ff ff  |..j......,j.....|
00000040  4c 4e 6a 07 f0 ff ff ff  50 58 6a 07 f0 ff ff ff  |LNj.....PXj.....|
00000050  34 55 6b 07 f0 ff ff ff  30 0a 6c 07 f0 ff ff ff  |4Uk.....0.l.....|
00000060  24 1d 6c 07 f0 ff ff ff  90 3a 6c 07 f0 ff ff ff  |$.l......:l.....|
00000070  64 4f 6c 07 f0 ff ff ff  18 5e 6c 07 f0 ff ff ff  |dOl......^l.....|
00000080  f4 71 6c 07 f0 ff ff ff  0c ed 6d 07 f0 ff ff ff  |.ql.......m.....|
00000090  98 33 6e 07 f0 ff ff ff  10 56 6e 07 f0 ff ff ff  |.3n......Vn.....|
000000a0  1c 64 6e 07 f0 ff ff ff  1c 70 6e 07 f0 ff ff ff  |.dn......pn.....|
000000b0  14 7e 6e 07 f0 ff ff ff  30 98 6e 07 f0 ff ff ff  |.~n.....0.n.....|
000000c0  c4 a3 6e 07 f0 ff ff ff  90 e2 6e 07 f0 ff ff ff  |..n.......n.....|
000000d0  78 7b 6f 07 f0 ff ff ff  b4 94 70 07 f0 ff ff ff  |x{o.......p.....|
000000e0  28 10 71 07 f0 ff ff ff  e4 07 72 07 f0 ff ff ff  |(.q.......r.....|
000000f0  d4 0f 72 07 f0 ff ff ff  20 1b 72 07 f0 ff ff ff  |..r..... .r.....|
<SNIP>
```

Or dump the section as a list of pointers

```bash
❯ ipsw macho dump kernelcache --section __DATA_CONST.__mod_init_func --addr --count 10

0xfffffff00769ba34
0xfffffff00769c20c
0xfffffff00769e598
0xfffffff00769fc18
0xfffffff0076a05b8
0xfffffff0076a0db0
0xfffffff0076a1908
0xfffffff0076a2cb4
0xfffffff0076a4e4c
0xfffffff0076a5850
```

Or write to a file for later post-processing

```bash
❯ ipsw macho dump kernelcache --section __DATA_CONST.__mod_init_func --size 656 --output mod_init_func.bin
   • Wrote data to file mod_init_func.bin
```

```bash
❯ hexdump -C mod_init_func.bin
00000000  34 ba 69 07 f0 ff ff ff  0c c2 69 07 f0 ff ff ff  |4.i.......i.....|
00000010  98 e5 69 07 f0 ff ff ff  18 fc 69 07 f0 ff ff ff  |..i.......i.....|
00000020  b8 05 6a 07 f0 ff ff ff  b0 0d 6a 07 f0 ff ff ff  |..j.......j.....|
00000030  08 19 6a 07 f0 ff ff ff  b4 2c 6a 07 f0 ff ff ff  |..j......,j.....|
00000040  4c 4e 6a 07 f0 ff ff ff  50 58 6a 07 f0 ff ff ff  |LNj.....PXj.....|
00000050  34 55 6b 07 f0 ff ff ff  30 0a 6c 07 f0 ff ff ff  |4Uk.....0.l.....|
00000060  24 1d 6c 07 f0 ff ff ff  90 3a 6c 07 f0 ff ff ff  |$.l......:l.....|
<SNIP>
```

### **macho info --help**

Help for macho cmd

```bash
❯ ipsw macho info --help

Explore a MachO file

Usage:
  ipsw macho info <macho> [flags]

Aliases:
  info, i

Flags:
  -z, --all-fileset-entries     Parse all fileset entries
  -a, --arch string             Which architecture to use for fat/universal MachO
  -b, --bit-code                Dump the LLVM bitcode
      --dump-cert               Dump the certificate
  -e, --ent                     Print entitlements
  -x, --extract-fileset-entry   Extract the fileset entry
  -t, --fileset-entry string    Which fileset entry to analyze
  -u, --fixups                  Print fixup chains
  -d, --header                  Print the mach header
  -h, --help                    help for info
  -j, --json                    Print the TOC as JSON
  -l, --loads                   Print the load commands
  -o, --objc                    Print ObjC info
  -r, --objc-refs               Print ObjC references
      --output string           Directory to extract files to
  -s, --sig                     Print code signature
  -g, --split-seg               Print split seg info
  -f, --starts                  Print function starts
  -c, --strings                 Print cstrings
  -n, --symbols                 Print symbols

Global Flags:
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### **macho info -d**

Similar to `otool -h`

```bash
❯ ipsw macho info JavaScriptCore

Magic         = 64-bit MachO
Type          = Dylib
CPU           = AARCH64, ARM64e (ARMv8.3) caps: PAC00
Commands      = 25 (Size: 4384)
Flags         = NoUndefs, DyldLink, TwoLevel, BindsToWeak, NoReexportedDylibs, AppExtensionSafe
```

### **macho info -l**

Similar to `otool -h -l`

```bash
❯ ipsw macho info JavaScriptCore

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

### **macho info --json**

Output the same information as `macho info --header --loads` but output as JSON

```bash
❯ ipsw macho info JavaScriptCore --json | jq . -C | less -Sr
```
```json
{
  "header": {
    "magic": "64-bit MachO",
    "type": "DYLIB",
    "cpu": "AARCH64, ARM64e caps: USR00",
    "commands": 24,
    "commands_size": 4736,
    "flags": [
      "NoUndefs",
      "DyldLink",
      "TwoLevel",
      "BindsToWeak",
      "NoReexportedDylibs",
      "AppExtensionSafe",
      "DylibInCache"
    ]
  },
  "loads": [
    {
      "load_cmd": "LC_SEGMENT_64",
      "len": 1112,
      "name": "__TEXT",
      "addr": 6885064704,
      "memsz": 21749760,
      "offset": 376832,
      "filesz": 21749760,
      "maxprot": "r-x",
      "prot": "r-x",
      "nsect": 13,
      "sections":
<SNIP>              
```

### **macho info --sig**

Similar to `jtool --sig`

```bash
❯ ipsw macho info /System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore --sig

Code Directory (167849 bytes)
	Version:     Scatter
	Flags:       None
	CodeLimit:   0x1477320
	Identifier:  com.apple.JavaScriptCore (@0x30)
	CDHash:      672d175a3045ec06f9c8e5d2ddc1ae04bf02f930d846ae820d3085bd884e24ac (computed)
	# of hashes: 5240 code (4096 pages) + 3 special
	Hashes @169 size: 32 Type: Sha256
		Special Slot   3 Resource Directory:	9c8adb9535f138fd28c8e42ecb03c25a98d81aeee8138a2a8f3588e5ace43dec
		Special Slot   2 Requirements Blob:	c8b0d11b77cd4a60abdd93b6776cf691b1f584e8511c434a58747524e8c280f9
		Special Slot   1 Bound Info.plist:	cf8085400b7145e1ae3d4b5eaf6037c3b6717bcab88570f5abc0b877961e5c30
		Slot   0 (File page @0x0000):	dfdea89e8455973ce1a138e53cc7859e33f8943448408831fedb1433953701ee
		Slot   1 (File page @0x1000):	24d72b5adb6f134eab447edb39566164855f03944a6135d7ee8295c18f041963
		Slot   2 (File page @0x2000):	8e42b49fb5dd11d989abdac71cfce2090c75524f0d66c3f6f060b6d8a85a307d
		Slot   3 (File page @0x3000):	3f856ada2dc70752622a75fbf773f77e25c2f67bfca97c1eaa6e859658642e41
		Slot   4 (File page @0x4000):	b507712eb7be07429fbb26151099ffc0b05ced7a752b0baf83e154f007d3b40a
		Slot   5 (File page @0x5000):	b07f51cc5ab8906003961fdce73df3fc85f4db6c6a7fcf49145cea2993a4b604
                <SNIP>
		Slot   5239 (File page @0x1477000):	862946908462dd3ee7ae0e2879846e1dc10f21f7705bac09b2172d43d035f145
Requirement Set (72 bytes) with 1 requirement
	0: Designated Requirement (@20, 72 bytes): identifier "com.apple.JavaScriptCore" and anchor apple
CMS (RFC3852) signature:
        OU: Apple Certification Authority CN: Apple Code Signing Certification Authority (2011-10-24 thru 2026-10-24)
        OU: Apple Certification Authority CN: Apple Root CA                              (2006-04-25 thru 2035-02-09)
        OU: Apple Certification Authority CN: Software Signing                           (2013-04-12 thru 2021-04-12)
```

:::info note
If you supply the `-V` flag, the output will be VERY similar to that of `openssl`
:::

### **macho info --dump-cert**

Dump certificate chain from the code signature

```bash
❯ ipsw macho info /Applications/1Password\ 7.app/Contents/MacOS/1Password\ 7 --dump-cert --output /tmp
   • Created /tmp/1Password 7.pem
```

To view the certificate chain, use the following command

```bash
❯ openssl crl2pkcs7 -nocrl -certfile /tmp/1Password\ 7.pem | openssl pkcs7  -print_certs -text | head -n20

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1763908746353189132 (0x187aa9a8c296210c)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Apple Inc., OU=Apple Certification Authority, CN=Apple Root CA
        Validity
            Not Before: Feb  1 22:12:15 2012 GMT
            Not After : Feb  1 22:12:15 2027 GMT
        Subject: CN=Developer ID Certification Authority, OU=Apple Certification Authority, O=Apple Inc., C=US
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:89:76:4f:06:5b:9a:41:ee:a5:23:2b:02:a3:5f:
                    d7:73:3f:c0:35:b0:8b:84:0a:3f:06:24:7f:a7:95:
                    3f:eb:4f:0e:93:af:b4:0e:d0:c8:3e:e5:6d:18:b3:
                    1f:e8:89:47:bf:d7:09:08:e4:ff:56:98:29:15:e7:
                    94:9d:b9:35:a3:0a:cd:b4:c0:e1:e2:60:f4:ca:ec:
                    29:78:45:69:69:60:6b:5f:8a:92:fc:9e:23:e6:3a:
```

### **macho info --ent**

Similar to `jtool --ent`

```bash
❯ ipsw macho info /usr/libexec/amfid --ent
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

### **macho info --objc**

Similar to `objdump --macho --objc-meta-data` OR `dsdump --objc -vv`

:::info note
Currently only supports _64-bit_ architechtures
:::

```bash
❯ ipsw macho info /usr/lib/libobjc.A.dylib --arch amd64 --objc | bat -l m
```

```objc
Objective-C
===========

@protocol NSObject
 @property (TQ,R) hash
 @property (T#,R) superclass
 @property (T@"NSString",R,C) description
 @property (T@"NSString",R,C) debugDescription

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
  // instance variables
  +0x00 # isa (0x8)

  // class methods
  0x000000210c8 +[Object initialize]
  0x000000210cc +[Object class]
  0x000000210d0 +[Object retain]
  0x000000210d4 +[Object release]
  0x000000210d5 +[Object autorelease]

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


0x00000035118 NSObject : <ROOT> <NSObject>
  // instance variables
  +0x00 # isa (0x8)

 @property (TQ,R) hash
 @property (T#,R) superclass
 @property (T@"NSString",R,C) description
 @property (T@"NSString",R,C) debugDescription

  // class methods
  0x00000007743 +[NSObject initialize]
  0x00000008d94 +[NSObject self]
  0x00000009b98 +[NSObject class]
  0x0000000d4fc +[NSObject superclass]
  0x00000013741 +[NSObject isMemberOfClass:]
  0x0000000c967 +[NSObject isKindOfClass:]
  0x0000000bd4e +[NSObject isSubclassOfClass:]
  0x00000011328 +[NSObject isAncestorOfObject:]
  0x00000010ca1 +[NSObject instancesRespondToSelector:]
  0x0000000bbd1 +[NSObject respondsToSelector:]
  0x0000000c999 +[NSObject conformsToProtocol:]
  0x0000000c6b8 +[NSObject hash]
  0x0000000c6bc +[NSObject isEqual:]
  0x000000223d5 +[NSObject isFault]
  0x000000223d8 +[NSObject isProxy]
  0x0000000bceb +[NSObject instanceMethodForSelector:]
  0x0000000f280 +[NSObject methodForSelector:]
  0x0000000b284 +[NSObject resolveClassMethod:]
  0x0000000acd7 +[NSObject resolveInstanceMethod:]
  0x000000223ea +[NSObject doesNotRecognizeSelector:]
  0x0000000e541 +[NSObject performSelector:]
  0x00000012a15 +[NSObject performSelector:withObject:]
  0x00000022428 +[NSObject performSelector:withObject:withObject:]
  0x00000022470 +[NSObject instanceMethodSignatureForSelector:]
  0x00000022482 +[NSObject methodSignatureForSelector:]
  0x00000022494 +[NSObject forwardInvocation:]
  0x000000224cf +[NSObject forwardingTargetForSelector:]
  0x000000224d2 +[NSObject description]
  0x000000224d5 +[NSObject debugDescription]
  0x00000009802 +[NSObject new]
  0x00000009c4e +[NSObject retain]
  0x000000224e2 +[NSObject _tryRetain]
  0x000000224e8 +[NSObject _isDeallocating]
  0x0000001163b +[NSObject allowsWeakReference]
  0x00000012761 +[NSObject retainWeakReference]
  0x0000000bbf7 +[NSObject release]
  0x0000000dd48 +[NSObject autorelease]
  0x000000224ec +[NSObject retainCount]
  0x00000008d54 +[NSObject alloc]
  0x00000009599 +[NSObject allocWithZone:]
  0x000000224fe +[NSObject init]
  0x00000022502 +[NSObject dealloc]
  0x0000000ff33 +[NSObject zone]
  0x00000022508 +[NSObject copy]
  0x0000000ff4c +[NSObject copyWithZone:]
  0x00000022510 +[NSObject mutableCopy]
  0x00000022514 +[NSObject mutableCopyWithZone:]

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


0x00000035118 NSObject : <ROOT> <NSObject>
  // instance variables
  +0x00 # isa (0x8)

 @property (TQ,R) hash
 @property (T#,R) superclass
 @property (T@"NSString",R,C) description
 @property (T@"NSString",R,C) debugDescription

  // class methods
  0x00000007743 +[NSObject initialize]
  0x00000008d94 +[NSObject self]
  0x00000009b98 +[NSObject class]
  0x0000000d4fc +[NSObject superclass]
  0x00000013741 +[NSObject isMemberOfClass:]
  0x0000000c967 +[NSObject isKindOfClass:]
  0x0000000bd4e +[NSObject isSubclassOfClass:]
  0x00000011328 +[NSObject isAncestorOfObject:]
  0x00000010ca1 +[NSObject instancesRespondToSelector:]
  0x0000000bbd1 +[NSObject respondsToSelector:]
  0x0000000c999 +[NSObject conformsToProtocol:]
  0x0000000c6b8 +[NSObject hash]
  0x0000000c6bc +[NSObject isEqual:]
  0x000000223d5 +[NSObject isFault]
  0x000000223d8 +[NSObject isProxy]
  0x0000000bceb +[NSObject instanceMethodForSelector:]
  0x0000000f280 +[NSObject methodForSelector:]
  0x0000000b284 +[NSObject resolveClassMethod:]
  0x0000000acd7 +[NSObject resolveInstanceMethod:]
  0x000000223ea +[NSObject doesNotRecognizeSelector:]
  0x0000000e541 +[NSObject performSelector:]
  0x00000012a15 +[NSObject performSelector:withObject:]
  0x00000022428 +[NSObject performSelector:withObject:withObject:]
  0x00000022470 +[NSObject instanceMethodSignatureForSelector:]
  0x00000022482 +[NSObject methodSignatureForSelector:]
  0x00000022494 +[NSObject forwardInvocation:]
  0x000000224cf +[NSObject forwardingTargetForSelector:]
  0x000000224d2 +[NSObject description]
  0x000000224d5 +[NSObject debugDescription]
  0x00000009802 +[NSObject new]
  0x00000009c4e +[NSObject retain]
  0x000000224e2 +[NSObject _tryRetain]
  0x000000224e8 +[NSObject _isDeallocating]
  0x0000001163b +[NSObject allowsWeakReference]
  0x00000012761 +[NSObject retainWeakReference]
  0x0000000bbf7 +[NSObject release]
  0x0000000dd48 +[NSObject autorelease]
  0x000000224ec +[NSObject retainCount]
  0x00000008d54 +[NSObject alloc]
  0x00000009599 +[NSObject allocWithZone:]
  0x000000224fe +[NSObject init]
  0x00000022502 +[NSObject dealloc]
  0x0000000ff33 +[NSObject zone]
  0x00000022508 +[NSObject copy]
  0x0000000ff4c +[NSObject copyWithZone:]
  0x00000022510 +[NSObject mutableCopy]
  0x00000022514 +[NSObject mutableCopyWithZone:]

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


@selectors refs
0x00000034e30 => 0x00000032b8f: load
0x00000034eb0 => 0x00000032c55: retainCount
0x00000034ef0 => 0x00000032e9b: dealloc
0x00000034e80 => 0x00000032c19: alloc
0x00000034ee0 => 0x00000032ccb: mutableCopyWithZone:
0x00000034e28 => 0x00000032b75: initialize
0x00000034e48 => 0x00000032bbc: new
0x00000034e58 => 0x00000032bc5: class
0x00000034ea0 => 0x00000032c3a: _tryRetain
0x00000034ec8 => 0x00000032d87: description
0x00000034ed0 => 0x00000032eaf: selector
0x00000034e50 => 0x00000032bc0: self
0x00000034e88 => 0x00000032c1f: allocWithZone:
0x00000034e98 => 0x00000032c2e: autorelease
0x00000034e68 => 0x00000032bda: respondsToSelector:
0x00000034ec0 => 0x00000032e96: init
0x00000034e38 => 0x00000032b94: allowsWeakReference
0x00000034e70 => 0x00000032bee: resolveInstanceMethod:
0x00000034ea8 => 0x00000032c45: _isDeallocating
0x00000034e20 => 0x00000032b87: release
0x00000034e78 => 0x00000032c05: resolveClassMethod:
0x00000034eb8 => 0x00000032ce0: copy
0x00000034ed8 => 0x00000032e0c: doesNotRecognizeSelector:
0x00000034ee8 => 0x00000032cbd: copyWithZone:
0x00000034e90 => 0x00000032b80: retain
0x00000034e40 => 0x00000032ba8: retainWeakReference
0x00000034e60 => 0x00000032bcb: isKindOfClass:

@methods
0x00000032d4a: isProxy
0x00000032e4a: methodSignatureForSelector:
0x00000032b80: retain
0x00000032bcb: isKindOfClass:
0x00000032c19: alloc
0x00000032c2e: autorelease
0x00000032caa: name
0x00000032cb8: hash
0x00000032c05: resolveClassMethod:
0x00000032c3a: _tryRetain
0x00000032ccb: mutableCopyWithZone:
0x00000032da6: isAncestorOfObject:
0x00000032dba: instancesRespondToSelector:
0x00000032cbd: copyWithZone:
0x00000032ce0: copy
0x00000032e9b: dealloc
0x00000032e26: instanceMethodSignatureForSelector:
0x00000032e96: init
0x00000032b75: initialize
0x00000032b87: release
0x00000032d23: performSelector:withObject:withObject:
0x00000032cf6: performSelector:
0x00000032dde: instanceMethodForSelector:
0x00000032e66: forwardInvocation:
0x00000032ba8: retainWeakReference
0x00000032d77: zone
0x00000032e0c: doesNotRecognizeSelector:
0x00000032bc5: class
0x00000032bda: respondsToSelector:
0x00000032c61: isa
0x00000032d63: conformsToProtocol:
0x00000032c71: descriptionForInstanceMethod:
0x00000032d7c: superclass
0x00000032eaf: selector
0x00000032eb8: finalize
0x00000032e79: forwardingTargetForSelector:
0x00000032b8f: load
0x00000032c8f: descriptionForClassMethod:
0x00000032d07: performSelector:withObject:
0x00000032d87: description
0x00000032dd6: isFault
0x00000032c55: retainCount
0x00000032bc0: self
0x00000032c65: conformsTo:
0x00000032ce5: debugDescription
0x00000032c1f: allocWithZone:
0x00000032d93: isSubclassOfClass:
0x00000032b94: allowsWeakReference
0x00000032bbc: new
0x00000032c45: _isDeallocating
0x00000032d52: isMemberOfClass:
0x00000032df9: methodForSelector:
0x00000032ea3: mutableCopy
0x00000032bee: resolveInstanceMethod:
0x00000032caf: isEqual:
```

### **macho info --fixups**

Print fixup chains

```bash
❯ ipsw macho info /Volumes/Sky19A344.N104N841OS/bin/ps --fixups

__DATA_CONST.__auth_got
0x100008000:  raw: 0xc009000000000000      auth-bind24: (next: 001, key: IA, addrDiv: 1, diversity: 0x0000, ordinal: 000)       libSystem.B.dylib/___error
0x100008008:  raw: 0xc009000000000001      auth-bind24: (next: 001, key: IA, addrDiv: 1, diversity: 0x0000, ordinal: 001)       libSystem.B.dylib/___stack_chk_fail
0x100008010:  raw: 0xc009000000000002      auth-bind24: (next: 001, key: IA, addrDiv: 1, diversity: 0x0000, ordinal: 002)       libSystem.B.dylib/___strlcat_chk
0x100008018:  raw: 0xc009000000000003      auth-bind24: (next: 001, key: IA, addrDiv: 1, diversity: 0x0000, ordinal: 003)       libSystem.B.dylib/___strlcpy_chk
0x100008020:  raw: 0xc009000000000004      auth-bind24: (next: 001, key: IA, addrDiv: 1, diversity: 0x0000, ordinal: 004)       libSystem.B.dylib/_access
0x100008028:  raw: 0xc009000000000005      auth-bind24: (next: 001, key: IA, addrDiv: 1, diversity: 0x0000, ordinal: 005)       libSystem.B.dylib/_asprintf
0x100008030:  raw: 0xc009000000000006      auth-bind24: (next: 001, key: IA, addrDiv: 1, diversity: 0x0000, ordinal: 006)       libSystem.B.dylib/_atoi
0x100008038:  raw: 0xc009000000000007      auth-bind24: (next: 001, key: IA, addrDiv: 1, diversity: 0x0000, ordinal: 007)       libSystem.B.dylib/_bsearch
0x100008040:  raw: 0xc009000000000008      auth-bind24: (next: 001, key: IA, addrDiv: 1, diversity: 0x0000, ordinal: 008)       libSystem.B.dylib/_calloc
0x100008048:  raw: 0xc009000000000009      auth-bind24: (next: 001, key: IA, addrDiv: 1, diversity: 0x0000, ordinal: 009)       libSystem.B.dylib/_compat_mode
0x100008050:  raw: 0xc00900000000000a      auth-bind24: (next: 001, key: IA, addrDiv: 1, diversity: 0x0000, ordinal: 010)       libSystem.B.dylib/_devname
0x100008058:  raw: 0xc00900000000000b      auth-bind24: (next: 001, key: IA, addrDiv: 1, diversity: 0x0000, ordinal: 011)       libSystem.B.dylib/_err
0x100008060:  raw: 0xc00900000000000c      auth-bind24: (next: 001, key: IA, addrDiv: 1, diversity: 0x0000, ordinal: 012)       libSystem.B.dylib/_errx
<SNIP>
__DATA_CONST.__got
0x100008218:  raw: 0x4008000000000043    arm64e bind24: (next: 001, ordinal: 067, addend: 0)    libSystem.B.dylib/__DefaultRuneLocale
0x100008220:  raw: 0x4008000000000044    arm64e bind24: (next: 001, ordinal: 068, addend: 0)    libSystem.B.dylib/___stack_chk_guard
0x100008228:  raw: 0x4008000000000045    arm64e bind24: (next: 001, ordinal: 069, addend: 0)    libSystem.B.dylib/___stderrp
0x100008230:  raw: 0x4008000000000046    arm64e bind24: (next: 001, ordinal: 070, addend: 0)    libSystem.B.dylib/___stdoutp
0x100008238:  raw: 0x4008000000000047    arm64e bind24: (next: 001, ordinal: 071, addend: 0)    libSystem.B.dylib/_mach_task_self_
0x100008240:  raw: 0x4008000000000048    arm64e bind24: (next: 001, ordinal: 072, addend: 0)    libSystem.B.dylib/_optarg
0x100008248:  raw: 0x4008000000000049    arm64e bind24: (next: 001, ordinal: 073, addend: 0)    libSystem.B.dylib/_optind
<SNIP>
```

### **macho info --fileset-entry**

Analyze FileSet entry MachO

```bash
❯ ipsw macho info Macmini9,1_J274AP_20E232/kernelcache.production --fileset-entry kernel

Magic         = 64-bit MachO
Type          = Exec
CPU           = AARCH64, ARM64e caps: KER00
Commands      = 30 (Size: 5904)
Flags         = NoUndefs, PIE, DylibInCache
000: LC_SEGMENT_64 sz=0x000c7ff8 off=0x00000000-0x000c7ff8 addr=0xfffffe0007b44000-0xfffffe0007c0c000 r-x/r-x   __TEXT
        sz=0x00034330 off=0x00001820-0x00035b50 addr=0xfffffe0007b45820-0xfffffe0007b79b50              __TEXT.__const
        sz=0x0007de25 off=0x00035b50-0x000b3975 addr=0xfffffe0007b79b50-0xfffffe0007bf7975              __TEXT.__cstring                 (CstringLiterals)
        sz=0x00014586 off=0x000b3975-0x000c7efb addr=0xfffffe0007bf7975-0xfffffe0007c0befb              __TEXT.__os_log
        sz=0x00000000 off=0x000c7efb-0x000c7efb addr=0xfffffe0007c0befb-0xfffffe0007c0befb              __TEXT.__thread_starts
        sz=0x000000f8 off=0x000c7f00-0x000c7ff8 addr=0xfffffe0007c0bf00-0xfffffe0007c0bff8              __TEXT.__eh_frame
<SNIP>
```

Extract a fileset entry to disk

```bash
❯ ipsw macho info Macmini9,1_J274AP_20E232/kernelcache.production --fileset-entry "com.apple.security.sandbox" --extract-fileset-entry

Magic         = 64-bit MachO
Type          = KextBundle
CPU           = AARCH64, ARM64e caps: KER00
Commands      = 9 (Size: 1304)
Flags         = NoUndefs, DyldLink, TwoLevel, DylibInCache
000: LC_SEGMENT_64 sz=0x00018aee off=0x00000000-0x00018aee addr=0xfffffe0007a10000-0xfffffe0007a2c000 r--/r--   __TEXT
        sz=0x00014362 off=0x00000580-0x000148e2 addr=0xfffffe0007a10580-0xfffffe0007a248e2              __TEXT.__const
        sz=0x000031f9 off=0x000148e2-0x00017adb addr=0xfffffe0007a248e2-0xfffffe0007a27adb              __TEXT.__cstring                 (CstringLiterals)
        sz=0x00001013 off=0x00017adb-0x00018aee addr=0xfffffe0007a27adb-0xfffffe0007a28aee              __TEXT.__os_log
001: LC_SEGMENT_64 sz=0x0002f2d0 off=0x00018aee-0x00047dbe addr=0xfffffe000a678000-0xfffffe000a6a8000 r-x/r-x   __TEXT_EXEC
        sz=0x0002e610 off=0x00018aee-0x000470fe addr=0xfffffe000a678000-0xfffffe000a6a6610              __TEXT_EXEC.__text              PureInstructions|SomeInstructions
        sz=0x00000cc0 off=0x000470fe-0x00047dbe addr=0xfffffe000a6a6610-0xfffffe000a6a72d0              __TEXT_EXEC.__stubs             PureInstructions|SomeInstructions (SymbolStubs)
002: LC_SEGMENT_64 sz=0x00004000 off=0x00047dbe-0x0004bdbe addr=0xfffffe000c048000-0xfffffe000c060000 rw-/rw-   __DATA
        sz=0x000002f8 off=0x00047dbe-0x000480b6 addr=0xfffffe000c048000-0xfffffe000c0482f8              __DATA.__data
        sz=0x00015fb0 off=0x00000000-0x00015fb0 addr=0xfffffe000c0482f8-0xfffffe000c05e2a8              __DATA.__bss                     (Zerofill)
003: LC_SEGMENT_64 sz=0x00002568 off=0x0004bdbe-0x0004e326 addr=0xfffffe000b620000-0xfffffe000b624000 rw-/rw-   __DATA_CONST
        sz=0x00000978 off=0x0004bdbe-0x0004c736 addr=0xfffffe000b620000-0xfffffe000b620978              __DATA_CONST.__got
        sz=0x00000008 off=0x0004c736-0x0004c73e addr=0xfffffe000b620978-0xfffffe000b620980              __DATA_CONST.__auth_ptr
        sz=0x00001be8 off=0x0004c73e-0x0004e326 addr=0xfffffe000b620980-0xfffffe000b622568              __DATA_CONST.__const
004: LC_SEGMENT_64 sz=0x00eb90e5 off=0x0004e326-0x00f0740b addr=0xfffffe000c180000-0xfffffe000d0390e5 r--/r--   __LINKEDIT
005: LC_SYMTAB                   Symbol offset=0x0054BEF6, Num Syms: "1238", String offset=0x005D1BFE-0x00F0740B
006: LC_DYSYMTAB
                     Local Syms: 923 at 0
                  External Syms: 8 at 923
                 Undefined Syms: 307 at 931
                            TOC: No
                         Modtab: No
        External symtab Entries: None
        Indirect symtab Entries: 575 at 0x005cb3da
         External Reloc Entries: None
            Local Reloc Entries: None
007: LC_UUID                     08D7639F-818E-3551-9B32-0565198961A8
008: LC_SOURCE_VERSION           1441.101.1.0.0
```

```bash
❯ ll

-rwxr-xr-x  1 blacktop    15M May  9 22:08 com.apple.security.sandbox
-rw-r--r--  1 blacktop    96M Apr 29 21:56 kernelcache.production
```

### **macho info --split-seg**

Dump the `LC_SEGMENT_SPLIT_INFO` of a KDK Kext

```bash
❯ ipsw macho info --arch arm64e --split-seg \
IOFireWireSerialBusProtocolSansPhysicalUnit.kext/Contents/MacOS/IOFireWireSerialBusProtocolSansPhysicalUnit
```
```bash
     __TEXT_EXEC.__text           0x0000400c  =>            __TEXT.__cstring        0x000005c8	kind(arm64_adrp)
     __TEXT_EXEC.__text           0x0000412c  =>            __TEXT.__cstring        0x000005c8	kind(arm64_adrp)
     __TEXT_EXEC.__text           0x00004464  =>            __TEXT.__cstring        0x000005c8	kind(arm64_adrp)
     __TEXT_EXEC.__text           0x00004010  =>            __TEXT.__cstring        0x000005c8	kind(arm64_off_12)
     __TEXT_EXEC.__text           0x00004130  =>            __TEXT.__cstring        0x000005c8	kind(arm64_off_12)
     __TEXT_EXEC.__text           0x00004468  =>            __TEXT.__cstring        0x000005c8	kind(arm64_off_12)
     __TEXT_EXEC.__text           0x00004300  =>            __TEXT.__cstring        0x0000066d	kind(arm64_adrp)
     __TEXT_EXEC.__text           0x00004304  =>            __TEXT.__cstring        0x0000066d	kind(arm64_off_12)
     __TEXT_EXEC.__text           0x000040fc  =>       __TEXT_EXEC.__auth_stubs     0x0000451c	kind(arm64_br_26)
     __TEXT_EXEC.__text           0x00004110  =>       __TEXT_EXEC.__auth_stubs     0x0000451c	kind(arm64_br_26)
     __TEXT_EXEC.__text           0x00004184  =>       __TEXT_EXEC.__auth_stubs     0x0000452c	kind(arm64_br_26)
     __TEXT_EXEC.__text           0x000041dc  =>       __TEXT_EXEC.__auth_stubs     0x0000452c	kind(arm64_br_26)
     __TEXT_EXEC.__text           0x00004020  =>       __TEXT_EXEC.__auth_stubs     0x0000453c	kind(arm64_br_26)
     __TEXT_EXEC.__text           0x00004140  =>       __TEXT_EXEC.__auth_stubs     0x0000453c	kind(arm64_br_26)
     __TEXT_EXEC.__text           0x00004478  =>       __TEXT_EXEC.__auth_stubs     0x0000453c	kind(arm64_br_26)
     __TEXT_EXEC.__text           0x00004048  =>       __TEXT_EXEC.__auth_stubs     0x0000454c	kind(arm64_br_26)
<SNIP>     
```       

### **macho info --bit-code**

Extract the LLVM bitcode from a MachO exported from iOS archive file

```bash
❯ ipsw macho info --bit-code <MACHO> --output /tmp/bc
```
```bash
LLVM Bitcode:
  Name:      Ld
  Version:   1.0
  Platform:  iOS
  Arch:      arm64
  SDK:       15.5
  Hide Syms: 1
  Linker Options:
    -execute
    -platform_version ios 15.5 15.5
    -e _main
    -rpath @executable_path/Frameworks
    -executable_path /Users/blacktop/Library/Developer/Xcode/DerivedData/App-gteiirrrrrixcmdujgfktocqukjq/Build/Intermediates.noindex/ArchiveIntermediates/App/InstallationBuildProductsLocation/Applications/App.app/App
    -dead_strip
  Dylibs:
    {SDKPATH}/System/Library/Frameworks/Foundation.framework/Foundation
    {SDKPATH}/usr/lib/libobjc.A.dylib
    {SDKPATH}/usr/lib/libSystem.B.dylib
    {SDKPATH}/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
    {SDKPATH}/System/Library/Frameworks/UIKit.framework/UIKit

   • Bitcode: -cc1 -triple arm64-apple-ios15.5.0 -emit-obj --mrelax-relocations -disable-llvm-passes -target-sdk-version=15.5 -fvisibility-inlines-hidden-static-local-var -fno-rounding-math -target-abi darwinpcs -Os
      • Extracting /tmp/bc/5.bc
   • Bitcode: -cc1 -triple arm64-apple-ios15.5.0 -emit-obj --mrelax-relocations -disable-llvm-passes -target-sdk-version=15.5 -fvisibility-inlines-hidden-static-local-var -fno-rounding-math -target-abi darwinpcs -Os
      • Extracting /tmp/bc/4.bc
   • Bitcode: -cc1 -triple arm64-apple-ios15.5.0 -emit-obj --mrelax-relocations -disable-llvm-passes -target-sdk-version=15.5 -fvisibility-inlines-hidden-static-local-var -fno-rounding-math -target-abi darwinpcs -Os
      • Extracting /tmp/bc/3.bc
   • Bitcode: -cc1 -triple arm64-apple-ios15.5.0 -emit-obj --mrelax-relocations -disable-llvm-passes -target-sdk-version=15.5 -fvisibility-inlines-hidden-static-local-var -fno-rounding-math -target-abi darwinpcs -Os
      • Extracting /tmp/bc/2.bc
   • Bitcode: -cc1 -triple arm64-apple-ios15.5.0 -emit-obj --mrelax-relocations -disable-llvm-passes -target-sdk-version=15.5 -fvisibility-inlines-hidden-static-local-var -fno-rounding-math -target-abi darwinpcs -Os
      • Extracting /tmp/bc/1.bc
```

Now to get LLVM IR disassembly from the bitcode files:

```bash
❯ llvm-dis /tmp/*.bc
```

```bash
❯ ls /tmp/bc
1.bc 1.ll 2.bc 2.ll 3.bc 3.ll 4.bc 4.ll 5.bc 5.ll
```

Take a look at the output

```bash
❯ cat /tmp/bc/1.ll
```
```llvm
; ModuleID = '/tmp/bc/1.bc'
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"
target triple = "arm64-apple-ios15.5.0"

%0 = type opaque
%1 = type opaque
%"__ir_hidden#19_" = type { i32*, i32, i8*, i64 }
%"__ir_hidden#20_" = type opaque
%"__ir_hidden#21_" = type { %"__ir_hidden#21_"*, %"__ir_hidden#21_"*, %"__ir_hidden#20_"*, i8* (i8*, i8*)**, %"__ir_hidden#22_"* }
%"__ir_hidden#22_" = type { i32, i32, i32, i8*, i8*, %"__ir_hidden#23_"*, %"__ir_hidden#25_"*, %"__ir_hidden#27_"*, i8*, %"__ir_hidden#29_"* }
```

### **macho disass**

Disassemble ARMv9 binaries

```bash
❯ ipsw macho disass --vaddr 0xfffffff007b7c05c kernelcache.release.iphone12.decompressed
```

```
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
❯ ipsw macho disass --symbol <SYMBOL_NAME> --instrs 200 JavaScriptCore
```

Make it pretty 💄🐷 using `--color` flag

```bash
❯ ipsw macho disass --vaddr 0xFFFFFFF007B44000 kernelcache.release.iphone13.decompressed --color
```

```armasm
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
❯ ipsw macho disass --demangle --symbol <SYMBOL_NAME> --instrs 200 JavaScriptCore --color
```

### **macho patch**

Patch MachO Load Commands

```bash
# Modify LC_BUILD_VERSION like vtool
❯ ipsw macho patch mod MACHO LC_BUILD_VERSION iOS 16.3 16.3 ld 820.1
# Add an LC_RPATH like install_name_tool
❯ ipsw macho patch add MACHO LC_RPATH @executable_path/Frameworks
```

### **macho sign**

Codesign a MachO

```bash
❯ ipsw macho sign --id com.apple.ls --ad-hoc --ent entitlements.plist /tmp/ls
? You are about to overwrite /tmp/ls. Continue? Yes
   • ad-hoc codesigning /tmp/ls
```

Check the signature

```bash
❯ codesign --verify --deep --strict --verbose=4 /tmp/ls
/tmp/ls: valid on disk
/tmp/ls: satisfies its Designated Requirement
```

### **macho search**

Search for MachOs that have split segments

```bash
❯ ipsw macho search --ipsw iPhone15,2_16.3_20D47_Restore.ipsw --load-command 'LC_SEGMENT_SPLIT_INFO'
   • Scanning FileSystem
/System/DriverKit/usr/lib/libSystem_debug.dylib	load=LC_SEGMENT_SPLIT_INFO
/System/DriverKit/usr/lib/system/libdispatch_debug.dylib	load=LC_SEGMENT_SPLIT_INFO
/System/DriverKit/usr/lib/system/libdispatch_profile.dylib	load=LC_SEGMENT_SPLIT_INFO
/System/DriverKit/usr/lib/system/libsystem_blocks_debug.dylib	load=LC_SEGMENT_SPLIT_INFO
/System/DriverKit/usr/lib/system/libsystem_blocks_profile.dylib	load=LC_SEGMENT_SPLIT_INFO
/System/DriverKit/usr/lib/system/libsystem_c_debug.dylib	load=LC_SEGMENT_SPLIT_INFO
/System/DriverKit/usr/lib/system/libsystem_malloc_debug.dylib	load=LC_SEGMENT_SPLIT_INFO
/System/DriverKit/usr/lib/system/libsystem_platform_debug.dylib	load=LC_SEGMENT_SPLIT_INFO
/System/DriverKit/usr/lib/system/libsystem_pthread_debug.dylib	load=LC_SEGMENT_SPLIT_INFO
/System/DriverKit/usr/lib/system/libsystem_trace_debug.dylib	load=LC_SEGMENT_SPLIT_INFO
/System/Library/Extensions/ASIOKit.kext/ASIOKit	load=LC_SEGMENT_SPLIT_INFO
/System/Library/Extensions/AppleGameControllerPersonality.kext/AppleGameControllerPersonality	load=LC_SEGMENT_SPLIT_INFO
/System/Library/Extensions/AppleUserConsent.kext/AppleUserConsent	load=LC_SEGMENT_SPLIT_INFO
/System/Library/Extensions/AppleUserConsent.kext/AppleUserConsent_development	load=LC_SEGMENT_SPLIT_INFO
/System/Library/Extensions/lifs.kext/lifs	load=LC_SEGMENT_SPLIT_INFO
/System/Library/PrivateFrameworks/iWorkImport.framework/iWorkImport	load=LC_SEGMENT_SPLIT_INFO
/usr/lib/dyld	load=LC_SEGMENT_SPLIT_INFO
/usr/lib/system/introspection/libdispatch.dylib	load=LC_SEGMENT_SPLIT_INFO
   • Scanning SystemOS
/System/Library/PrivateFrameworks/VisualTestKit.framework/VisualTestKit	load=LC_SEGMENT_SPLIT_INFO
/usr/lib/libstdc++.6.0.9.dylib	load=LC_SEGMENT_SPLIT_INFO
/usr/lib/libstdc++.6.dylib	load=LC_SEGMENT_SPLIT_INFO
/usr/lib/libstdc++.dylib	load=LC_SEGMENT_SPLIT_INFO
   • Scanning AppOS
```

Search for MachOs that impliment an ObjC protocol

```bash 
❯ ipsw macho search --ipsw iPhone15,2_16.3_20D47_Restore.ipsw --protocol 'NSObject'

   • Scanning filesystem
/Applications/AAUIViewService.app/AAUIViewService	protocol=NSObject
/Applications/AMSEngagementViewService.app/AMSEngagementViewService	protocol=NSObject
/Applications/AXRemoteViewService.app/AXRemoteViewService	protocol=NSObject
/Applications/AXUIViewService.app/AXUIViewService	protocol=NSObject
/Applications/AccountAuthenticationDialog.app/AccountAuthenticationDialog	protocol=NSObject
/Applications/ActivityMessagesApp.app/PlugIns/ActivityMessagesExtension.appex/ActivityMessagesExtension	protocol=NSObject
/Applications/AirDropUI.app/AirDropUI	protocol=NSObject
/Applications/AirPlayReceiver.app/AirPlayReceiver	protocol=NSObject
/Applications/AnimojiStickers.app/AnimojiStickers	protocol=NSObject
/Applications/AnimojiStickers.app/PlugIns/AnimojiStickersExtension.appex/AnimojiStickersExtension	protocol=NSObject
/Applications/AppSSOUIService.app/AppSSOUIService	protocol=NSObject
/Applications/AppStore.app/AppStore	protocol=NSObject
/Applications/AppStore.app/PlugIns/AppStoreWidgetsExtension.appex/AppStoreWidgetsExtension	protocol=NSObject
/Applications/AppStore.app/PlugIns/ProductPageExtension.appex/ProductPageExtension	protocol=NSObject
/Applications/AppStore.app/PlugIns/SubscribePageExtension.appex/SubscribePageExtension	protocol=NSObject
/Applications/Apple TV Remote.app/Apple TV Remote	protocol=NSObject
/Applications/Apple TV Remote.app/PlugIns/TVRemoteIntentExtension.appex/TVRemoteIntentExtension	protocol=NSObject
/Applications/AskPermissionUI.app/AskPermissionUI	protocol=NSObject
/Applications/AuthKitUIService.app/AuthKitUIService	protocol=NSObject
/Applications/AuthenticationServicesUI.app/AuthenticationServicesUI	protocol=NSObject
<SNIP>
```
