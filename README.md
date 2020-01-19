<p align="center">
  <a href="https://github.com/blacktop/ipsw"><img alt="IPSW Logo" src="https://raw.githubusercontent.com/blacktop/ipsw/master/hack/ipsw.png" height="140" /></a>
  <h1 align="center">ipsw</h1>
  <h4><p align="center">Download and parse ipsw(s) from <a href="https://ipsw.me">ipsw.me</a> or <a href="https://www.theiphonewiki.com/wiki/Firmware">theiphonewiki.com</a></p></h4>
  <p align="center">
    <a href="https://actions-badge.atrox.dev/blacktop/ipsw/got" alt="Actions">
          <img src="https://github.com/blacktop/ipsw/workflows/Go/badge.svg" /></a>
    <a href="https://ci.appveyor.com/project/blacktop/ipsw" alt="AppVeyor">
          <img src="https://ci.appveyor.com/api/projects/status/jcx0faojt820p5w4?svg=true" /></a>
    <a href="https://github.com/blacktop/ipsw/releases/latest" alt="Downloads">
          <img src="https://img.shields.io/github/downloads/blacktop/ipsw/total.svg" /></a>
    <a href="https://github.com/blacktop/ipsw/releases" alt="GitHub Release">
          <img src="https://img.shields.io/github/release/blacktop/ipsw.svg" /></a>
    <a href="http://doge.mit-license.org" alt="LICENSE">
          <img src="https://img.shields.io/:license-mit-blue.svg" /></a>
</p>

## Install

### macOS

```bash
$ brew install blacktop/tap/ipsw
```

### windows

Download from [releases](https://github.com/blacktop/ipsw/releases/latest)

### linux/docker

[![Docker Stars](https://img.shields.io/docker/stars/blacktop/ipsw.svg)](https://hub.docker.com/r/blacktop/ipsw/) [![Docker Pulls](https://img.shields.io/docker/pulls/blacktop/ipsw.svg)](https://hub.docker.com/r/blacktop/ipsw/) [![Docker Image](https://img.shields.io/badge/docker%20image-114MB-blue.svg)](https://hub.docker.com/r/blacktop/ipsw/)

```bash
$ docker pull blacktop/ipsw
```

## Getting Started

```bash
$ ipsw --help

Download and Parse IPSWs

Usage:
  ipsw [command]

Available Commands:
  device-list     List all iOS devices
  device-tree     Parse DeviceTree
  dis             Disassemble ARM binaries at address or symbol
  download        Download and parse IPSW(s) from the internets
  dyld            Parse dyld_shared_cache
  extract         Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW
  help            Help about any command
  info            Display IPSW Info
  kernel          Parse kernelcache
  macho           Parse a MachO file
  version         Print the version number of ipsw

Flags:
  -h, --help      help for ipsw
  -V, --verbose   verbose output

Use "ipsw [command] --help" for more information about a command.
```

### `download`

#### Download an `ipsw` and extract/decompress the `kernelcache`

```bash
$ ipsw download --device iPhone11,2 --build 16A366

   • Getting IPSW              build=16A366 device=iPhone11,2 signed=true version=12.0
      3.4 GiB / 3.4 GiB [==========================================================| 00:00 ] 79.08 MiB/s
      • verifying sha1sum...

$ ipsw extract --kernel iPhone11,2_12.0_16A366_Restore.ipsw

   • Extracting Kernelcache from IPSW
      • Parsing Compressed Kernelcache
         • compressed size: 17842843, uncompressed: 35727352. unknown: 0x3f9543fd, unknown 1: 0x1
      • Decompressing Kernelcache
```

Notice that the `kernelcache` was extracted from the `ipsw` and decompressed :smiling_imp:

```bash
$ file kernelcache.release.iphone11.decompressed

kernelcache.release.iphone11.decompressed: "Mach-O 64-bit executable arm64"
```

#### Download all the iOS 12.0 `ipsws`

```bash
$ ipsw download --version 12.0

? You are about to download 17 ipsw files. Continue? Yes
   • Getting IPSW              build=16A366 device=iPhone11,4 signed=true version=12.0
    3.3 GiB / 3.3 GiB [==========================================================| 00:00 ] 59.03 MiB/s
      • verifying sha1sum...
   • Getting IPSW              build=16A366 device=iPod7,1 signed=true version=12.0
    734.7 MiB / 2.6 GiB [===============>------------------------------------------| 00:57 ] 44.84 MiB/s
  ...
```

#### Download all the LATEST `ipsws`

Queries the iTunes XML for latest version _(maybe run this as a cron job)_ 😉

```bash
$ ipsw download -V latest --yes --black-list AppleTV --black-list iPod7,1
   • Latest iOS release found is: "12.4.1"
      • "Yo, ain't no one jailbreaking this shizz NOT even Ian Beer my dude!!!! 😏"
   • Getting IPSW              build=16G77 device=iPhone6,2 version=12.4.1
        363.0 MiB / 2.9 GiB [======>-----------------------------------------------| 18:52 ] 49.18 MiB/s
  ...
```

> **NOTE:** you must do **one** device type/family per `--black-list` or `--white-list` flag

To grab _only_ the iPods

```bash
$ ipsw download -V latest --yes --white-list ipod
   • Latest iOS release found is: "12.4.1"
      • "Yo, ain't no one jailbreaking this shizz NOT even Ian Beer my dude!!!! 😏"
   • Getting IPSW              build=16G77 device=iPod9,1 version=12.4.1
        363.0 MiB / 2.9 GiB [======>-----------------------------------------------| 18:52 ] 49.18 MiB/s
  ...
```

This will also generate a `checksums.txt.sha1` file that you can use to verify the downloads

```bash
$ sha1sum -c checksums.txt.sha1

iPad_64bit_TouchID_13.2.3_17B111_Restore.ipsw: OK
iPadPro_9.7_13.2.3_17B111_Restore.ipsw: OK
iPad_Educational_13.2.3_17B111_Restore.ipsw: OK
```

#### Only download and `decompress` the kernelcaches _(not supported on Windows)_

Single `kernelcache`

```bash
ipsw download kernel --device iPhone11,2 --build 16B92
```

All of dem!!!

```bash
$ time ipsw download kernel --version 12.0.1

"8.40s user 1.19s system 53% cpu 17.784 total"
```

That's **14** decompressed kernelcaches in under **9 seconds** :smirk:

```bash
$ ls -1

kernelcache.release.ipad4b.decompressed
kernelcache.release.ipad5b.decompressed
kernelcache.release.ipad6b.decompressed
kernelcache.release.ipad6d.decompressed
kernelcache.release.ipad6f.decompressed
kernelcache.release.ipad7.decompressed
kernelcache.release.iphone10b.decompressed
kernelcache.release.iphone11.decompressed
kernelcache.release.iphone11b.decompressed
kernelcache.release.iphone7.decompressed
kernelcache.release.iphone8b.decompressed
kernelcache.release.iphone9.decompressed
kernelcache.release.j42d.decompressed
kernelcache.release.n102.decompressed
```

But, how does it work?? 🤔 With the POWER :muscle: of [partialzip](https://github.com/blacktop/partialzip) !!

#### Only download files that match a given name/path

```bash
$ ipsw download -v 13.2.3 -d iPhone12,3 pattern Firmware/all_flash/iBoot
```

```bash
$ ls iBoot*
iBoot.d321.RELEASE.im4p        iBoot.d331p.RELEASE.im4p.plist
iBoot.d321.RELEASE.im4p.plist  iBoot.d421.RELEASE.im4p
iBoot.d331.RELEASE.im4p        iBoot.d421.RELEASE.im4p.plist
iBoot.d331.RELEASE.im4p.plist  iBoot.d431.RELEASE.im4p
iBoot.d331p.RELEASE.im4p       iBoot.d431.RELEASE.im4p.plist
```

#### Download BETA `ipsws`

This is done by scraping [theiphonewiki.com](https://theiphonewiki.com).

```bash
$ ipsw download beta 17C5046a
```

#### Download with a Proxy

This will download and decompress the `kernelcache` for an `iPhone XS` running `iOS 12.1` behind a corporate proxy

```bash
$ ipsw download --proxy http://proxy.org:[PORT] --device iPhone11,2 --build 16B92
```

To disable cert verification

```bash
$ ipsw download --insecure --device iPhone11,2 --build 16B92
```

### `info` 🆕

Display `info` about IPSWs

```bash
$ ipsw info iPhone12,3_17D5044a_Restore.ipsw

[IPSW Info]
===========
Version        = 13.3.1
BuildVersion   = 17D5044a
OS Type        = "Development"
FileSystem     = 038-19665-018.dmg (Type: APFS)

Devices
-------

iPhone XS Max)
 - iPhone11,6_D331PAP_17D5044a
   - KernelCache: kernelcache.release.iphone11
   - CPU: A12 Bionic (ARMv8.3-A), ID: t8020

iPhone 11 Pro)
 - iPhone12,3_D421AP_17D5044a
   - KernelCache: kernelcache.release.iphone12
   - CPU: A13 Bionic (ARMv8.3-A), ID: t8030

iPhone XS)
 - iPhone11,2_D321AP_17D5044a
   - KernelCache: kernelcache.release.iphone11
   - CPU: A12 Bionic (ARMv8.3-A), ID: t8020

iPhone 11 Pro Max)
 - iPhone12,5_D431AP_17D5044a
   - KernelCache: kernelcache.release.iphone12
   - CPU: A13 Bionic (ARMv8.3-A), ID: t8030
```

Or remotely

```bash
$ ipsw info --remote https://updates.cdn-apple.com/../iPodtouch_7_13.3_17C54_Restore.ipsw
```

### `extract` _(not supported on Windows)_

#### Extract `kernelcache` from a previously downloaded `ipsw`

```bash
$ ipsw extract --kernel iPhone11,2_12.0_16A366_Restore.ipsw
```

#### Extract `dyld_shared_cache` from a previously downloaded `ipsw`

- `macOS`

```bash
$ ipsw extract --dyld iPhone11,2_12.0_16A366_Restore.ipsw
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
             blacktop/ipsw -V extract --dyld iPhone11_2_12.4.1_16G102_Restore.ipsw
```

### `kernel kexts` 🆕

List all the kernelcache's KEXTs

```bash
$ ipsw kernel kexts kernelcache.release.iphone12.decompressed

FOUND: 230
com.apple.kpi.mach (19.2.0)
com.apple.kpi.private (19.2.0)
com.apple.kpi.unsupported (19.2.0)
com.apple.kpi.iokit (19.2.0)
com.apple.kpi.libkern (19.2.0)
com.apple.kpi.bsd (19.2.0)
com.apple.iokit.IONetworkingFamily (3.4)
com.apple.iokit.IOTimeSyncFamily (810.1)
com.apple.iokit.IOPCIFamily (2.9)
com.apple.driver.IOACIPCFamily (1)
com.apple.iokit.IOSkywalkFamily (1)
com.apple.driver.AppleIPAppender (1.0)
<SNIP>
```

### `dyld webkit`

Extract WebKit version from `dyld_shared_cache`

```bash
$ ipsw dyld webkit dyld_shared_cache
   • WebKit Version: 607.2.6.0.1
```

### `dyld list` 🆕

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

### `dyld symaddr` 🆕

Find symbol _(unslid)_ addresses in shared cache

```bash
$ ipsw dyld symaddr dyld_shared_cache <SYMBOL_NAME>
```

Speed it up by supplying the dylib name

```bash
$ ipsw dyld symaddr --image JavaScriptCore dyld_shared_cache <SYMBOL_NAME>
```

> **NOTE:** you don't have to supply the full image path

### `dyld split` _(only on macOS)_

Split up a `dyld_shared_cache`

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

### `decompress` _(not supported on Windows)_

Decompress a previously extracted `kernelcache`

```bash
$ ipsw kernel decompress kernelcache.release.iphone11
```

### Parse DeviceTrees

Print out SUMMARY

```bash
$ ipsw download -v 13.3 -d iPhone12,3 pattern DeviceTree
$ ipsw device-tree DeviceTree.d431ap.im4p
      • Product Name: iPhone 11 Pro Max
      • Model: iPhone12,5
      • BoardConfig: D431AP
```

Or print out JSON

```bash
$ ipsw device-tree --json DeviceTree.d431ap.im4p | jq .
```

```json
{
  "device-tree": {
    "#address-cells": 2,
    "#size-cells": 2,
    "AAPL,phandle": 1,
    "children": [
      {
        "chosen": {
          "#address-cells": 2,
          "AAPL,phandle": 2,
   <SNIP>
```

Or remotely

```bash
$ ipsw device-tree --remote https://updates.cdn-apple.com/../iPodtouch_7_13.3_17C54_Restore.ipsw

   • DeviceTree.n112ap.im4p
      • Product Name: iPod touch
      • Model: iPod9,1
      • BoardConfig: N112AP
```

### `macho` [WIP] :construction:

Similar to `otool -h -l`

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

### `dis` [WIP] :construction:

Working on getting a disassembler working

> **NOTE:** requires **capstone** installed from the `next` branch _(brew install capstone --HEAD)_

```bash
$ ipsw dis --vaddr 0xfffffff007b7c05c kernelcache.release.iphone12.decompressed
```

```s
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
$ ipsw dis --symbol <SYMBOL_NAME> --instrs 200 JavaScriptCore
```

Make it pretty 💄🐷 using [bat](https://github.com/sharkdp/bat)

```bash
$ ipsw dis --vaddr 0xfffffff007b7c05c --instrs 100 kernelcache.release.iphone12.decompressed \
   | bat -p --tabs 0 -l s
```

Demangle C++ names

```bash
$ ipsw dis --symbol <SYMBOL_NAME> --instrs 200 JavaScriptCore | c++filt | bat -p -l s --tabs 0
```

### `diff` [WIP] :construction:

I am playing with the idea of `diffing` kernelcaches by creating directory structures of Apple's src from assert strings.

Then you could use `git diff` or something to get a quick **high** level view of what Apple has changed by seeing new files being added or removed as well as seeing the line numbers of the assert strings move around.

```bash
$ ipsw kernel diff kernelcache.release.iphone11
```

You can see an example of what this outputs [HERE](https://github.com/blacktop/ipsw/tree/master/pkg/kernelcache/diff/Library/Caches/com.apple.xbs/Sources)

### Add `zsh` completions

Pick a folder in your `$fpath` to write the completion to.

> **NOTE:** I'm using `/usr/local/share/zsh-completions`

```bash
$ ipsw completion zsh > /usr/local/share/zsh-completions/_ipsw
$ rm -f ~/.zcompdump; compinit
```

=OR=

Add the following to your `~/.zshrc`

```bash
autoload -Uz compinit && compinit -C
source <(ipsw completion zsh)
compdef _ipsw ipsw
```

## TODO

- [x] use https://github.com/gocolly/colly
- [ ] create offline copy of ipsw.me API
- [ ] https://github.com/xerub/img4lib
- [ ] devicetree read/write
- [x] parse plists for folder creation

## Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/blacktop/ipsw/issues/new)

## License

MIT Copyright (c) 2018 **blacktop**
