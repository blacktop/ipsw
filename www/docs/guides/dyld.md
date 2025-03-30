---
description: All the MANY ways you can parse DSC files.
---
# Parse dyld_shared_cache

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
| SEG        | INITPROT | MAXPROT | SIZE    | ADDRESS                | FILE OFFSET          | SLIDE INFO OFFSET    | FLAGS |
| ---------- | -------- | ------- | ------- | ---------------------- | -------------------- | -------------------- | ----- |
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

:::info note
We added the `-s` or `--sig` flag to also parse the _CodeDirectory_.
:::

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

:::info note
In macOS12+/iOS15+ caches replaced this data with `prebuilt loader sets` which contain much of the same data and are still VERY powerful  *(this cmd outputs both types)*
:::

### **dyld extract**

Extract dylib from *dyld_shared_cache*

```bash
❯ ipsw dyld extract dyld_shared_cache_arm64e JavaScriptCore
   • Created JavaScriptCore
```

Extract all dylibs from *dyld_shared_cache*

```bash
❯ ipsw dyld extract dyld_shared_cache_arm64e --all
   • Extracting all dylibs from dyld_shared_cache_arm64e
      ✅  [=============================================================| 2700/2700 ]
```

:::info note
This command allows you to extract dylibs on non-darwin systems and it will add all local symbols to the symbol table as well as apply the DSC slide info for the pages included in the dylib if you supply the `--slide` flag *(this removes PACed pointers)*
 
🆕 We recently added 2 new flags:
 - `--objc` that "symbolicates" ObjC runtime info *(classes, class methods instance methods, categories, etc.)*
 - `--stubs` that "symbolicates" all the addresses that point to StubIsland stubs *(**NOTE:** right now this adds ALL them, in the future we'll try and only add the needed stubs)*

> **NOTE:** This isn't repairing the ObjC runtime data or patching stubs, it's just adding the symbols to the symbol table so you can use them in your analysis.
:::

:::caution

This command isn't 💯 done yet and is missing some features:
- [ ] Repairing the ObjC runtime data
- [ ] Patching the stubs  
- [ ] 🤔 Create an [issue](https://github.com/blacktop/ipsw/issues) if you would like something else added

The goal with this command is to 1) create "near" perfect dylibs that can be used as stand alone frameworks and 2) create dylibs for reverse engineering *(packed with symbols etc)* for use in tools like Ghidra.
:::

### **dyld macho**

Parse a cached `dylib` MachO file

```bash
❯ ipsw dyld macho --help
Parse a dylib file

Usage:
  ipsw dyld macho <dyld_shared_cache> <dylib> [flags]

Flags:
  -a, --all             Parse ALL dylibs
  -x, --extract         🚧 Extract the dylib
      --force           Overwrite existing extracted dylib(s)
  -h, --help            help for macho
  -j, --json            Print the TOC as JSON
  -l, --loads           Print the load commands
  -o, --objc            Print ObjC info
  -r, --objc-refs       Print ObjC references
      --output string   Directory to extract the dylib(s)
      --search string   Search for byte pattern
  -f, --starts          Print function starts
  -s, --strings         Print cstrings
  -b, --stubs           Print stubs
  -n, --symbols         Print symbols

Global Flags:
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

#### Print a dylibs load commands AND dump the ObjC runtime data

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

```objc
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

:::info note
Make the output look amazing by piping to `bat -l m --tabs 0 -p --theme Nord --wrap=never --pager "less -S"`
:::

#### Dump a dylib's header as JSON

```bash
❯ ipsw dyld macho dyld_shared_cache_arm64e JavaScriptCore --json | jq . -C | less -Sr
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
      "sections": [
        {
          "name": "__text",
          "segment": "__TEXT",
          "addr": 6885070320,
          "size": 20555936,
          "offset": 382448,
          "align": 4,
          "reloff": 0,
          "nreloc": 0,
          "type": 64
        },
<SNIP>        
```

#### Search for byte pattern

```bash
❯ ipsw dyld macho dyld_shared_cache_arm64e JavaScriptCore --search "7f 23 03 d5 * * * * f6 57 01 a9"

Search Results
--------------
0x199f25c80
0x199f26804
0x199f285c4
0x199f286c4
0x199f28860
0x199f289d8
0x199f2966c
<SNIP>
```

### **dyld stubs**

Print out the 🆕 stubs islands

```bash
❯ ipsw dyld stubs dyld_shared_cache_arm64e | head
   • Loading symbol cache file...
0x199ce7640: _CMPhotoJPEGWriteMPFWithJPEG
0x1ad5d5970: _objc_autorelease
0x1c8d0f350: _$ss10_HashTableV12previousHole6beforeAB6BucketVAF_tF
0x1cf7eba00: _$s5TeaUI14KeyCommandItemVMa
0x1bb1f8a40: _swift_task_switch
0x1ec2127d0: _CGColorGetColorSpace
0x207434db0: __swift_stdlib_strtod_clocale
0x1a0622e00: _objc_retain_x20
0x1c1f87d30: _swift_getTupleTypeLayout3
0x1bb220d70: _fcntl
```

### **dyld symaddr**

Find all instances of a symbol's _(unslid)_ addresses in shared cache

```bash
❯ ipsw dyld symaddr dyld_shared_cache <SYMBOL_NAME> --all
```

Speed it up by supplying the dylib name

```bash
❯ ipsw dyld symaddr --image JavaScriptCore dyld_shared_cache <SYMBOL_NAME>
```

:::info note
You don't have to supply the full image path
:::

Dump ALL teh symbolz!!!

```bash
❯ ipsw dyld symaddr dyld_shared_cache
```

Read in a JSON symbol lookup file

```bash
❯ jq . sym_lookup.json
[
  {
    "pattern": "__platform_memmove",
    "image": "libsystem_platform.dylib"
  },
  {
    "pattern": "_memcpy",
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

:::info note
This will also create a cached version of the lookup hash table (.a2s) so the next time you lookup it will be much faster
:::

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
❯ ipsw dyld objc --class dyld_shared_cache_arm64e

0x2180bb240: APClientInfoUI	            AdPlatformsCommonUI
0x1dd4ccf40: FLFollowUpAction	            CoreFollowUp
0x1dd47d338: ProcessAnalytics	            SymptomAnalytics
0x1dda0ffb8: SBPosterBoardUpdateManager	SpringBoard
0x1ddfbca18: NEIPv6Settings	            NetworkExtension
0x2180bc130: QLExtension	               QuickLookSupport
0x218898148: AXAlertAction	               AXSpringBoardServerInstance
0x1dd606e98: _CPLOptimisticIDMapping	   CloudPhotoLibrary
0x2186ec0d8: AUGenericViewController	   CoreAudioKit
<SNIP>
```

Dump all the protocols

```bash
❯ ipsw dyld objc --proto dyld_shared_cache

0x1dd1489c8: NCNotificationListMigrationSchedulerDelegate	UserNotificationsUIKit
0x1dd1d3688: SBSceneHandleObserverToken	                  SpringBoardUI
    0x1dd09f288: _SFDynamicBarAnimatorStateObserver	SafariServices
    0x1dd09f288: _SFDynamicBarAnimatorStateObserver	MobileSafariUI
0x1dd0a9608: IXCoordinatorWithInstallOptions	   InstallCoordination
0x1dd096288: SFCompanionServiceManagerProtocol	Sharing
0x1dd0a8ee8: ATXEngagementRecordManagerProtocol	AppPredictionClient
    0x1dd121368: WFParameterEventObserver	WorkflowKit
    0x1dd121368: WFParameterEventObserver	WorkflowEditor
    0x1dd121368: WFParameterEventObserver	WorkflowEditor
```

Dump all the selectors

```bash
❯ ipsw dyld objc --sel dyld_shared_cache

0x18307bd68: rtiDocumentState
0x18527926c: _grabUserActivityTitleWithCallback:
0x1856042a9: deleteHistoryWithCompletion:
0x185017e2f: releaseViewManager
0x182e62aa2: getAssetPathForLocale:
0x183c89b23: T@"AVMomentCaptureMovie",&,N,V_movie
```

Dump all the imp-caches

```bash
❯ ipsw dyld objc --imp-cache dyld_shared_cache
```

### **dyld objc class**

Lookup a class's address *(same as `ipsw dyld objc --class`)*

```bash
❯ ipsw dyld objc class dyld_shared_cache release

0x1b92c85a8: release
```

Or get all the classes for an image

```bash
❯ ipsw dyld objc class --image libobjc.A.dylib dyld_shared_cache
```

### **dyld objc proto**

Lookup a protocol's address *(same as `ipsw dyld objc --proto`)*

```bash
❯ ipsw dyld objc proto dyld_shared_cache release

0x1b92c85a8: release
```

### **dyld objc sel**

Lookup a selector's address *(same as `ipsw dyld objc --sel`)*

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

To use an specific version of Xcode

```bash
❯ ipsw dyld split dyld_shared_cache_arm64e --xcode ~/Downloads/Xcode_12.5.1.app
```

To create a `~/Library/Developer/Xcode/iOS DeviceSupport/` folder from a _dyld_shared_cache_ to symbolicate a remote `lldb` session

```bash
❯ ipsw dyld split dyld_shared_cache_arm64e --cache --version 16.3 --build 20D5035i
   • Splitting dyld_shared_cache to ~/Library/Developer/Xcode/iOS DeviceSupport/16.3 (20D5035i) arm64e
   • Creating Xcode cache ~/Library/Developer/Xcode/iOS DeviceSupport/16.3 (20D5035i) arm64e/Info.plist
0/2700
1/2700
2/2700
3/2700
4/2700
5/2700
6/2700
7/2700
8/2700
<SNIP>
```

```bash
❯ ls -1 ~/Library/Developer/Xcode/iOS\ DeviceSupport/
14.4.1 (18D61)
14.4.2 (18D70)
16.0 (20A5303i) arm64e
16.0 (20A5328h) arm64e
16.0 (20A5339d) arm64e
"16.3 (20D5035i) arm64e" 👀
```

:::info note
This commnd calls into Xcode's `dsc_extractor.bundle` so will ALWAYS work as long as your have a recent version of Xcode installed
:::

:::info note
If you are on a **non-darwin** system use the `ipsw dyld extract` command instead.  You can use the `ipsw dyld extract` command on **darwin** systems as well, however, it will be slower than using the `dsc_extractor.bundle` based `ipsw dyld split` command and *(for now)* only improves on the output by also applying the DSC slide-info if you use the `--slide` flag.  Eventually `ipsw dyld extract` will be able to create **near** perfect dylib extractions and will be the preferred command and this one will only be useful when Apple releases the next major OS version and inevitably breaks everyones DSC parsing 😏 again, but you can count on `ipsw` to once again be the FIRST to figure it out again 😁
:::

### **dyld webkit**

Extract WebKit version from _dyld_shared_cache_

```bash
❯ ipsw dyld webkit dyld_shared_cache_arm64e
   • WebKit Version: 614.4.4.0.3
```

### **dyld patches**

List dyld patch info

```bash
❯ ipsw dyld patches dyld_shared_cache_arm64e
[PATCHES] /usr/lib/libobjc.A.dylib	(258 symbols)
0x1800c799c: _class_respondsToSelector
    0x1de608458: (diversity: 0x0000, key: IA, auth: true) /usr/lib/swift/libswiftCore.dylib
    0x1de667330: (diversity: 0x0000, key: IA, auth: true) /System/Library/Frameworks/Foundation.framework/Foundation
    0x1de6a66b8: (diversity: 0x0000, key: IA, auth: true) /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
    0x1de7e38f8: (diversity: 0x0000, key: IA, auth: true) /System/Library/Frameworks/CoreData.framework/CoreData
    0x1dec4ef48: (diversity: 0x0000, key: IA, auth: true) /System/Library/PrivateFrameworks/GameCenterUI.framework/GameCenterUI
    0x1def62d30: (diversity: 0x0000, key: IA, auth: true) /System/Library/PrivateFrameworks/GameCenterFoundation.framework/GameCenterFoundation
    0x1df072928: (diversity: 0x0000, key: IA, auth: true) /System/Library/PrivateFrameworks/WorkflowKit.framework/WorkflowKit
    0x1e234a1c8: (diversity: 0x0000, key: IA, auth: true) GOT
    0x21a88fce8: (diversity: 0x0000, key: IA, auth: true) GOT
0x1800bec28: _objc_setProperty_nonatomic
    0x1de667bd0: (diversity: 0x0000, key: IA, auth: true) /System/Library/Frameworks/Foundation.framework/Foundation
    0x1de7e3e70: (diversity: 0x0000, key: IA, auth: true) /System/Library/Frameworks/CoreData.framework/CoreData
    0x1de84b178: (diversity: 0x0000, key: IA, auth: true) /System/Library/PrivateFrameworks/AccessibilityUtilities.framework/AccessibilityUtilities
    0x1de9e0da0: (diversity: 0x0000, key: IA, auth: true) /System/Library/PrivateFrameworks/IMSharedUtilities.framework/IMSharedUtilities
    0x1e06c5ac0: (diversity: 0x0000, key: IA, auth: true) /System/Library/PrivateFrameworks/CoreUI.framework/CoreUI
    0x1deaa96c0: (diversity: 0x0000, key: IA, auth: true) /System/Library/PrivateFrameworks/Message.framework/Message
<SNIP>    
```

```bash
❯ ipsw dyld patches dyld_shared_cache_arm64e -i libdyld.dylib
[PATCHES] /usr/lib/system/libdyld.dylib	(98 symbols)
0x1a81ccbf4: __dyld_find_protocol_conformance_on_disk
    0x1de608270: (key: IA, auth: true)                    /usr/lib/swift/libswiftCore.dylib
    0x1de6083a8: (diversity: 0x0000, key: IA, auth: true) /usr/lib/swift/libswiftCore.dylib
0x1a81caf30: _dlopen_preflight
    0x1de6a6888: (diversity: 0x0000, key: IA, auth: true) /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
    0x218ed9bc8: (diversity: 0x0000, key: IA, auth: true) /System/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/DVTInstrumentsFoundation
    0x1e2304f18: (diversity: 0x0000, key: IA, auth: true) GOT
0x1a81ca71c: _dyld_image_header_containing_address
    0x1e2304fb0: (diversity: 0x0000, key: IA, auth: true) GOT
    0x1e23085d0: (diversity: 0x0000, key: IA, auth: true) GOT
    0x1e2304fb0: (diversity: 0x0000, key: IA, auth: true) GOT
    0x1e23085d0: (diversity: 0x0000, key: IA, auth: true) GOT
    0x1e2304fb0: (diversity: 0x0000, key: IA, auth: true) GOT
<SNIP>    
```

```bash
❯ ipsw dyld patches dyld_shared_cache_arm64e -i libdyld.dylib -s _dlopen | head
0x1a81cada8: _dlopen
    0x1de667530: (diversity: 0x0000, key: IA, auth: true) /System/Library/Frameworks/Foundation.framework/Foundation
    0x1de6a6880: (diversity: 0x0000, key: IA, auth: true) /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
    0x1de6bbed0: (diversity: 0x0000, key: IA, auth: true) /System/Library/Frameworks/CoreGraphics.framework/CoreGraphics
    0x1de7ac910: (diversity: 0x0000, key: IA, auth: true) /System/Library/Frameworks/SwiftUI.framework/SwiftUI
    0x1de7e3a88: (diversity: 0x0000, key: IA, auth: true) /System/Library/Frameworks/CoreData.framework/CoreData
    0x1de816db8: (diversity: 0x0000, key: IA, auth: true) /System/Library/Frameworks/ContactsUI.framework/ContactsUI
    0x1de84ae68: (diversity: 0x0000, key: IA, auth: true) /System/Library/PrivateFrameworks/AccessibilityUtilities.framework/AccessibilityUtilities
    0x1de885910: (diversity: 0x0000, key: IA, auth: true) /System/Library/PrivateFrameworks/AppleMediaServices.framework/AppleMediaServices
    0x1de8e0620: (diversity: 0x0000, key: IA, auth: true) /System/Library/Frameworks/Contacts.framework/Contacts
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

### **dyld str**

Scan _dyld_shared_cache_ for strings

```bash
❯ ipsw dyld str dyld_shared_cache_arm64e --pattern "fuck"
```

```
0x1bae9dfe4: (DialogEngine)	"fucking"
0x1bae9dff4: (DialogEngine)	"fuckar"
0x1bae9fc8b: (DialogEngine)	"motherfucker"
0x1baea059e: (DialogEngine)	"fuckfinger"
<SNIP>
0x1e1d8afb8: (DifferentialPrivacy)	"motherfucker"
0x1e1d8bdd8: (DifferentialPrivacy)	"mindfucker"
0x1e1d8bdf8: (DifferentialPrivacy)	"mindfuck"
0x1ec0dcf66: (ResponseKit)	"what the fuck"
0x2195d9728: (ResponseKit)	"what the fuck"
<SNIP>
```

🫢 daaaaang Apple's got a real potty mouth 😏 

:::info note
The `--pattern` option supports regex and for some reason is the fastest way to search for strings in the cache. I'm not sure why, but it's faster than `str1 == str2` comparison 🤷‍♂️
:::   

### **dyld swift**

Dump Swift Optimizations Info *(`type` conformances, `foreign` type conformances and `metadata` conformances)*

```bash
❯ ipsw dyld swift dyld_shared_cache_arm64e --demangle --types
   • Loading symbol cache file...
0x4060a8: type_descriptor: 0x4c54ff9c, protocol: 0x118cd50, proto_conformance: 0x4c54ffb8, dylib_objc_index: 707
    0x1cc54ff9c: T n/a                                                  NewsAnalytics
    0x18118cd50: P protocol descriptor for CustomDebugStringConvertible libswiftCore.dylib
    0x1cc54ffb8: C n/a                                                  NewsAnalytics
0x22ded8: type_descriptor: 0x1414227c, protocol: 0x1189df4, proto_conformance: 0x14142398, dylib_objc_index: 72
    0x19414227c: T n/a                               libVFXCore.dylib
    0x181189df4: P protocol descriptor for Equatable libswiftCore.dylib
    0x194142398: C n/a                               libVFXCore.dylib
0x22e058: type_descriptor: 0x14142510, protocol: 0x11884fc, proto_conformance: 0x1414259c, dylib_objc_index: 72
    0x194142510: T n/a                                      libVFXCore.dylib
<SNIP>    
```

:::info note
The `--demangle` option is only avabile on **darwin** hosts for now, as it calls into a dylib.
:::

### **dyld a2o**

Convert _dyld_shared_cache_ address to offset

```bash
❯ ipsw dyld a2o dyld_shared_cache_arm64e 0x1D7B18000
   • Offset  dec=37994496 ext=".27.dylddata" hex=0x243c000 mapping=__LINKEDIT stubs=false uuid=DC237E9C-4500-345E-8C4B-54F12BE73741
```

### **dyld o2a**

Convert _dyld_shared_cache_ offset to address

```bash
❯ ipsw dyld o2a dyld_shared_cache_arm64e 0x243c000
   • dyld4 cache with stub islands detected (will search within dyld_subcache_entry cacheVMOffsets)
   • Address  dec=6480445440 ext=".01" hex=0x18243c000 mapping=__TEXT stubs=false uuid=836E3AA5-1E8F-38F9-AFC5-60DF76027BAD
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

:::info note
You can speed up symbol lookups by supplying the `--image` flag or you can use the `--vaddr` flag
:::

```armasm
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

:::info note
Make the output look amazing by adding the `--color` flag 🌈
:::

### **dyld imports**

List all dylibs that import/load a given dylib in the _dyld_shared_cache_

```bash
❯ ipsw dyld imports dyld_shared_cache JavaScriptCore

JavaScriptCore Imported By:
===========================

In DSC (Dylibs)
---------------
/System/Library/PrivateFrameworks/WebGPU.framework/WebGPU
/System/Library/PrivateFrameworks/WebCore.framework/WebCore
/System/Library/Frameworks/WebKit.framework/WebKit
/System/Library/PrivateFrameworks/JetEngine.framework/JetEngine
/System/Library/Frameworks/SafariServices.framework/SafariServices
/System/Library/PrivateFrameworks/SafariShared.framework/SafariShared
/System/Library/PrivateFrameworks/SafariSharedUI.framework/SafariSharedUI
/System/Library/PrivateFrameworks/JetUI.framework/JetUI
/System/Library/PrivateFrameworks/ProVideo.framework/ProVideo
/System/Library/PrivateFrameworks/StoreKitUI.framework/StoreKitUI
/System/Library/PrivateFrameworks/WorkflowKit.framework/WorkflowKit
/System/Library/PrivateFrameworks/SeymourServices.framework/SeymourServices
/System/Library/Frameworks/VideoSubscriberAccount.framework/VideoSubscriberAccount
/System/Library/PrivateFrameworks/MobileSafariUI.framework/MobileSafariUI
/System/Library/PrivateFrameworks/WebKitLegacy.framework/WebKitLegacy
/System/Library/PrivateFrameworks/AppStoreKit.framework/AppStoreKit
/System/Library/PrivateFrameworks/AppStoreKitInternal.framework/AppStoreKitInternal
/System/Library/PrivateFrameworks/ITMLKit.framework/ITMLKit
/System/Library/PrivateFrameworks/VideosUI.framework/VideosUI
/System/Library/PrivateFrameworks/TelephonyPreferences.framework/TelephonyPreferences
/System/Library/PrivateFrameworks/CoreChart.framework/CoreChart
/System/Library/PrivateFrameworks/RemoteUI.framework/RemoteUI
/System/Library/PrivateFrameworks/MetricsKit.framework/MetricsKit
/System/Library/PrivateFrameworks/WebBookmarks.framework/WebBookmarks
/System/Library/PrivateFrameworks/WebUI.framework/WebUI
/System/Library/PrivateFrameworks/CommunicationsSetupUI.framework/CommunicationsSetupUI
/System/Library/PrivateFrameworks/TuriCore.framework/TuriCore
/System/Library/PrivateFrameworks/Cards.framework/Cards
/System/Library/PrivateFrameworks/WebInspector.framework/WebInspector
/System/Library/PrivateFrameworks/iTunesStoreUI.framework/iTunesStoreUI
/System/Library/PrivateFrameworks/MailWebProcessSupport.framework/MailWebProcessSupport
/System/Library/PrivateFrameworks/JITAppKit.framework/JITAppKit
/System/Library/PrivateFrameworks/MusicUI.framework/MusicUI
/System/Library/PrivateFrameworks/TVMLKit.framework/TVMLKit
/System/Library/PrivateFrameworks/WorkflowEditor.framework/WorkflowEditor
/System/Library/PrivateFrameworks/MobileSafari.framework/PlugIns/Safari.wkbundle/Safari
/System/Library/PrivateFrameworks/SlideshowKit.framework/Frameworks/OpusKit.framework/OpusKit
/System/Library/PrivateFrameworks/AirPlayKit.framework/AirPlayKit
/System/Library/PrivateFrameworks/TouchML.framework/TouchML
/System/Library/PrivateFrameworks/ActionKit.framework/ActionKit
/System/Library/PrivateFrameworks/WebApp.framework/WebApp
/System/Library/PrivateFrameworks/WebSheet.framework/WebSheet
/System/Library/PrivateFrameworks/VideoSubscriberAccountUI.framework/VideoSubscriberAccountUI

In FileSystem DMG (Apps)
------------------------
/Applications/DataActivation.app/DataActivation
/Applications/MTLReplayer.app/MTLReplayer
/Applications/VideoSubscriberAccountViewService.app/VideoSubscriberAccountViewService
/System/Library/PrivateFrameworks/ActionPredictionHeuristics.framework/XPCServices/HeuristicInterpreter.xpc/HeuristicInterpreter
/System/Library/PrivateFrameworks/AppStoreComponents.framework/Support/appstorecomponentsd
/System/Library/PrivateFrameworks/AppleMediaServicesUI.framework/amsengagementd
/System/Library/PrivateFrameworks/AppleMediaServicesUIDynamic.framework/XPCServices/AppleMediaServicesUIDynamicService.xpc/AppleMediaServicesUIDynamicService
/System/Library/PrivateFrameworks/VideoSubscriberAccountUI.framework/PlugIns/VideoSubscriberAccountAuthenticationExtension.appex/VideoSubscriberAccountAuthenticationExtension
/cdhash/0254faebce8593aaefd5db2b95696a33ff3c9880 (/usr/libexec/proactiveeventtrackerd)
/cdhash/0361ef8633f63f58a344a1f6b44a5883229d11a1 (/Applications/DataActivation.app/DataActivation)
/cdhash/25ef8201f35f9244c6c8ca460cd894cef7b9b86d (/System/Library/PrivateFrameworks/VideoSubscriberAccountUI.framework/PlugIns/VideoSubscriberAccountAuthenticationExtension.appex/VideoSubscriberAccountAuthenticationExtension)
/cdhash/3b863c1ce76a2c31a12a8983c80a139a44d67516 (/System/Library/PrivateFrameworks/AppleMediaServicesUIDynamic.framework/XPCServices/AppleMediaServicesUIDynamicService.xpc/AppleMediaServicesUIDynamicService)
/cdhash/4f9e0310bc4ed6f771eed1bcefa383961edfa57b (/System/Library/PrivateFrameworks/ActionPredictionHeuristics.framework/XPCServices/HeuristicInterpreter.xpc/HeuristicInterpreter)
/cdhash/52afe0df81978225c8408fb42adbd722f4fcced3 (/System/Library/PrivateFrameworks/AppleMediaServicesUI.framework/amsengagementd)
/cdhash/83198ea295da0df64f43a5379433448f401a8a52 (/Applications/MTLReplayer.app/MTLReplayer)
/cdhash/8722d3a31074cf78f16d3d50000c237fffb7072e (/Applications/VideoSubscriberAccountViewService.app/VideoSubscriberAccountViewService)
/cdhash/d87d78b5f59981e4bcbcf13368cd90985da78b76 (/System/Library/PrivateFrameworks/AppStoreComponents.framework/Support/appstorecomponentsd)
/usr/libexec/proactiveeventtrackerd
```

:::info note
Notice we also got the filesystem's binaries that import that dylib??? That's due to the POWER 💪 of `prebuilt loader sets` 😎
:::

For a more comprehensive list of imports run

```bash
❯ ipsw dyld imports --file-system iPhone15,2_16.3_20D47_Restore.ipsw JavaScriptCore
```

### **dyld xref**

List all the cross-references in the _dyld_shared_cache_ for a given virtual address

```bash
❯ ipsw dyld symaddr dyld_shared_cache_arm64e _NSLog
0x1813450bc:    (local|regular) _NSLog  Foundation
0x1813450bc:    (symtab|external|__TEXT.__text) _NSLog  Foundation
```

Search the dylib that the symbol is in by default

```bash
❯ ipsw dyld xref dyld_shared_cache_arm64e 0x1813450bc
   • parsing public symbols...
   • parsing private symbols...
   • parsing stub islands...  
   • Searching for xrefs (use -V for more progess output)
   • XREFS                     dylib=Foundation sym=_NSLog xrefs=314

0x1818e4d8c: -[NSFileVersion setResolved:] + 120
0x1812a5228: -[NSString rangeOfString:options:range:locale:] + 196
0x1818e2400: ___36-[NSFileSubarbitrationClaim granted]_block_invoke.71 + 20
0x1817f3b8c: ___52-[NSExtensionItem _matchingDictionaryRepresentation]_block_invoke + 440
0x181330ad4: -[NSFileCoordinator(NSPrivate) _blockOnAccessClaim:withAccessArbiter:] + 320
0x18137e384: ___51-[NSBackgroundActivityScheduler scheduleWithBlock:]_block_invoke + 400
0x1818259b0: -[NSPlaceholderMutableString initWithCString:encoding:] + 124
0x181869b70: -[__NSConcreteURLComponents setPercentEncodedQueryItems:] + 304
0x1812b88e0: -[NSPlaceholderString initWithBytes:length:encoding:] + 112
0x1813036a8: -[NSString(NSPathUtilities) stringByAppendingPathExtension:] + 532
0x181874ad4: -[NSPlaceholderValue getValue:] + 36
0x18188c088: -[NSCorrectionCheckingResult initWithCoder:] + 264
0x1812fd1e8: -[NSThread start] + 260
0x1817d48f8: -[NSMutableCharacterSet invert] + 60
0x1817cb6f8: -[NSBigMutableString _createSubstringWithRange:] + 156
0x181808e84: ___62-[NSURL(NSURLPromisedItems) _valueFromFaultDictionary:forKey:]_block_invoke + 112
0x1818257bc: -[NSPlaceholderMutableString initWithBytesNoCopy:length:encoding:freeWhenDone:] + 104
0x181838c80: +[NSMessagePort sendBeforeTime:streamData:components:to:from:msgid:reserved:] + 476
<SNIP>
```
:::info note
- To search ALL dylibs, use the `--all` flag  
- To search a specific dylib, use the `--image` flag  
- To search all other dylibs that import the dylib that contains the symbol/address, use the `--imports` flag  

:::

:::info
This is one of `ipsw`'s MOST powerful commands and is getting better all the time.  Check back periodically and see what's new!
:::

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
   sz="0x000002d8" off=0x502c2428-0x502c2700 addr="0x1d22c2428"-0x1d22c2700   __DATA_CONST.__got
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
❯ ipsw dyld dump dyld_shared_cache_arm64e 0x1d22c2428 --size 728 --addr \
               | xargs -I {} /bin/zsh -c 'ipsw dyld a2s dyld_shared_cache_arm64e {}'

   • Address dylib=CoreFoundation section=__DATA_CONST.__const
0x1d9a84600: _NSCalendarIdentifierGregorian

   • Address dylib=Foundation section=__DATA_CONST.__const
0x1d9a8ba90: _NSCocoaErrorDomain

   • Address dylib=Foundation section=__DATA.__common
0x1d6d83b52: _NSDeallocateZombies

   • Address dylib=/Foundation section=__DATA_CONST.__const
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

To dump a section from a dylib in the _dyld_shared_cache_

```bash
❯ ipsw dyld dump dyld_shared_cache --image JavaScriptCore --section __TEXT.__cstring --size 208
   • Address location          dylib=JavaScriptCore section=__TEXT.__cstring
000000019ba27290:  41 70 70 72 6f 78 69 6d  61 74 65 28 00 20 73 65  |Approximate(. se|
000000019ba272a0:  63 29 00 4e 4f 54 20 49  4d 50 4c 45 4d 45 4e 54  |c).NOT IMPLEMENT|
000000019ba272b0:  45 44 20 59 45 54 0a 00  41 53 53 45 52 54 49 4f  |ED YET..ASSERTIO|
000000019ba272c0:  4e 20 46 41 49 4c 45 44  3a 20 25 73 0a 00 53 48  |N FAILED: %s..SH|
000000019ba272d0:  4f 55 4c 44 20 4e 45 56  45 52 20 42 45 20 52 45  |OULD NEVER BE RE|
000000019ba272e0:  41 43 48 45 44 0a 00 41  53 53 45 52 54 49 4f 4e  |ACHED..ASSERTION|
000000019ba272f0:  20 46 41 49 4c 45 44 3a  20 00 0a 25 73 0a 00 41  | FAILED: ..%s..A|
000000019ba27300:  52 47 55 4d 45 4e 54 20  42 41 44 3a 20 25 73 2c  |RGUMENT BAD: %s,|
000000019ba27310:  20 25 73 0a 00 00 46 41  54 41 4c 20 45 52 52 4f  | %s...FATAL ERRO|
000000019ba27320:  52 3a 20 00 0a 00 55 6e  6b 6e 6f 77 6e 20 6c 6f  |R: ...Unknown lo|
000000019ba27330:  67 67 69 6e 67 20 6c 65  76 65 6c 3a 20 25 73 00  |gging level: %s.|
000000019ba27340:  55 6e 6b 6e 6f 77 6e 20  6c 6f 67 67 69 6e 67 20  |Unknown logging |
000000019ba27350:  63 68 61 6e 6e 65 6c 3a  20 25 73 00 25 40 00 25  |channel: %s.%@.%|
```
