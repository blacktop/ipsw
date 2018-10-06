# ipsw

[![Circle CI](https://circleci.com/gh/blacktop/ipsw.png?style=shield)](https://circleci.com/gh/blacktop/ipsw) [![Github All Releases](https://img.shields.io/github/downloads/blacktop/ipsw/total.svg)](https://github.com/blacktop/ipsw/releases/latest) [![GitHub release](https://img.shields.io/github/release/blacktop/ipsw.svg)](https://github.com/blacktop/ipsw/releases) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)

> Download and parse ipsw(s) from [ipsw.me](https://ipsw.me) or [theiphonewiki.com](https://theiphonewiki.com)

---

## Install

### macOS

```bash
$ brew install blacktop/tap/ipsw
```

### linux/windows

Download from [releases](https://github.com/blacktop/ipsw/releases/latest)

## Getting Started

```bash
$ ipsw --help

Usage: ipsw [OPTIONS] COMMAND [arg...]

IPSW Downloader

Version: 18.09.7, BuildTime: 2018-10-06T19:57:00Z
Author:
  blacktop - <https://github.com/blacktop>

Options:
  --verbose, -V  verbose output
  --help, -h     show help
  --version, -v  print the version

Commands:
  generate  crawl theiphonewiki.com and create JSON database
  extract   extract and decompress a kernelcache
  download  download and parse ipsw from the internet
  help      Shows a list of commands or help for one command

Run 'ipsw COMMAND --help' for more information on a command.
```

### `download`

#### Download an `ipsw` and extract/decompress the `kernelcache`

```bash
$ ipsw --device iPhone11,2 --build 16A366 --dec

   • Getting IPSW              build=16A366 device=iPhone11,2 signed=true version=12.0
      3.4 GiB / 3.4 GiB [==========================================================| 00:00 ] 79.08 MiB/s
      • verifying md5sum...
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
$ ipsw download --iversion 12.0 --dec

? You are about to download 17 ipsw files. Continue? Yes
   • Getting IPSW              build=16A366 device=iPhone11,4 signed=true version=12.0
	   3.3 GiB / 3.3 GiB [==========================================================| 00:00 ] 59.03 MiB/s
      • verifying md5sum...
   • Extracting Kernelcache from IPSW
   • Parsing Compressed Kernelcache
      • compressed size: 17842843, uncompressed: 35727352. unknown: 0x3f9543fd, unknown 1: 0x1
   • Decompressing Kernelcache
   • Getting IPSW              build=16A366 device=iPod7,1 signed=true version=12.0
	   734.7 MiB / 2.6 GiB [===============>------------------------------------------| 00:57 ] 44.84 MiB/s
  ...
```

### `extract`

Extract `kernelcache` from a previously downloaded `ipsw`

```bash
$ ipsw extract iPhone11,2_12.0_16A366_Restore.ipsw
```

## TODO

- [ ] use https://github.com/gocolly/colly
- [ ] create offline copy of ipsw.me API
- [ ] download simultaniously to decrease total time _(need to limit concurrent downloads and 17+ at a time could be bad)_

## Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/blacktop/ipsw/issues/new)

## License

MIT Copyright (c) 2018 **blacktop**
