# ipsw

[![Circle CI](https://circleci.com/gh/blacktop/ipsw.png?style=shield)](https://circleci.com/gh/blacktop/ipsw) [![Build status](https://ci.appveyor.com/api/projects/status/jcx0faojt820p5w4?svg=true)](https://ci.appveyor.com/project/blacktop/ipsw)
[![Github All Releases](https://img.shields.io/github/downloads/blacktop/ipsw/total.svg)](https://github.com/blacktop/ipsw/releases/latest) [![GitHub release](https://img.shields.io/github/release/blacktop/ipsw.svg)](https://github.com/blacktop/ipsw/releases) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)

> Download and parse ipsw(s) from [ipsw.me](https://ipsw.me) or [theiphonewiki.com](https://theiphonewiki.com)

---

## Install

### macOS

``` bash
$ brew install blacktop/tap/ipsw
```

### linux/windows

Download from [releases](https://github.com/blacktop/ipsw/releases/latest)

### docker

[![Docker Stars](https://img.shields.io/docker/stars/blacktop/ipsw.svg)](https://hub.docker.com/r/blacktop/ipsw/) [![Docker Pulls](https://img.shields.io/docker/pulls/blacktop/ipsw.svg)](https://hub.docker.com/r/blacktop/ipsw/) [![Docker Image](https://img.shields.io/badge/docker%20image-114MB-blue.svg)](https://hub.docker.com/r/blacktop/ipsw/)

``` bash
$ docker pull blacktop/ipsw
```

## Getting Started

``` bash
$ ipsw --help

Download and Parse IPSWs

Usage:
  ipsw [command]

Available Commands:
  completion  Generates bash completion scripts
  device      Parse DeviceTree
  download    Download and parse IPSW(s) from the internets
  dyld        Parse dyld_shared_cache
  extract     Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW
  help        Help about any command
  kernel      Parse kernelcache
  version     Print the version number of ipsw

Flags:
      --config string   config file (default is $HOME/.ipsw.yaml)
  -h, --help            help for ipsw
  -V, --verbose         verbose output

Use "ipsw [command] --help" for more information about a command.
```

### `download`

#### Download an `ipsw` and extract/decompress the `kernelcache`

``` bash
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

``` bash
$ file kernelcache.release.iphone11.decompressed

kernelcache.release.iphone11.decompressed: "Mach-O 64-bit executable arm64"
```

#### Download all the iOS 12.0 `ipsws`

``` bash
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

Queries iTunes XML for latest version _(maybe run this as a cron job)_ 😉

``` bash
$ ipsw download -V latest --yes --black-list AppleTV --black-list iPod7,1
   • Latest iOS release found is: "12.4.1"
      • "Yo, ain't no one jailbreaking this shizz NOT even Ian Beer my dude!!!! 😏"
   • Getting IPSW              build=16G77 device=iPhone6,2 version=12.4.1
        363.0 MiB / 2.9 GiB [======>-----------------------------------------------| 18:52 ] 49.18 MiB/s
  ...
```

> **NOTE:** you must do **one** device type/family per `--black-list` or `--white-list` flag

To grab *only* the iPods

``` bash
$ ipsw download -V latest --yes --white-list ipod
   • Latest iOS release found is: "12.4.1"
      • "Yo, ain't no one jailbreaking this shizz NOT even Ian Beer my dude!!!! 😏"
   • Getting IPSW              build=16G77 device=iPod9,1 version=12.4.1
        363.0 MiB / 2.9 GiB [======>-----------------------------------------------| 18:52 ] 49.18 MiB/s
  ...
```

#### Only download and decompress the kernelcaches _(which is CRAZY fast)_

Single `kernelcache`

``` bash
ipsw download kernel --device iPhone11,2 --build 16B92
```

All of dem!!!

``` bash
$ time ipsw download kernel --version 12.0.1

"8.40s user 1.19s system 53% cpu 17.784 total"
```

That's **14** decompressed kernelcaches in under **9 seconds** :smirk:

``` bash
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

#### Download with a Proxy

This will download and decompress the `kernelcache` for an `iPhone XS` running `iOS 12.1` behind a corporate proxy

``` bash
$ ipsw download --proxy http://proxy.org:[PORT] --device iPhone11,2 --build 16B92
```

To disable cert verification

``` bash
$ ipsw download --insecure --device iPhone11,2 --build 16B92
```

### `extract`

#### Extract `kernelcache` from a previously downloaded `ipsw`

``` bash
$ ipsw extract --kernel iPhone11,2_12.0_16A366_Restore.ipsw
```

#### Extract `dyld_shared_cache` from a previously downloaded `ipsw`

`macOS`

``` bash
$ ipsw extract --dyld iPhone11,2_12.0_16A366_Restore.ipsw
   • Extracting dyld_shared_cache from IPSW
   • Mounting DMG
   • Extracting System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e to dyld_shared_cache
   • Unmounting DMG
```

`docker` 🆕

``` bash
$ docker run --init -it --rm \
             --device /dev/fuse \
             --cap-add=SYS_ADMIN \
             -v `pwd`:/data \
             blacktop/ipsw -V extract --dyld iPhone11_2_12.4.1_16G102_Restore.ipsw
```

### `webkit`

Extract WebKit version from `dyld_shared_cache`

``` bash
$ ipsw dyld webkit dyld_shared_cache
   • WebKit Version: 607.2.6.0.1
```

### `split` _(only on macOS)_ 🆕

Split up a `dyld_shared_cache`

``` bash
$ ipsw dyld split dyld_shared_cache
   • Splitting dyld_shared_cache

0/1445
1/1445
2/1445
3/1445
<SNIP>
1440/1445
1441/1445
1442/1445
1443/1445
1444/1445
```

### `decompress`

Decompress a previously extracted `kernelcache`

``` bash
$ ipsw kernel decompress kernelcache.release.iphone11
```

### `diff` [WIP] :construction:

I am playing with the idea of `diffing` kernelcaches by creating directory structures of Apple's src from assert strings.

Then you could use `git diff` or something to get a quick **high** level view of what Apple has changed by seeing new files being added or removed as well as seeing the line numbers of the assert strings move around.

``` bash
$ ipsw kernel diff kernelcache.release.iphone11
```

You can see an example of what this outputs [HERE](https://github.com/blacktop/ipsw/tree/master/kernelcache/diff/Library/Caches/com.apple.xbs/Sources)

## TODO

* [ ] use https://github.com/gocolly/colly
* [ ] create offline copy of ipsw.me API
* [ ] download simultaniously to decrease total time _(need to limit concurrent downloads and 17+ at a time could be bad)_

## Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/blacktop/ipsw/issues/new)

## License

MIT Copyright (c) 2018 **blacktop**

