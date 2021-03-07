<p align="center">
  <a href="https://github.com/blacktop/ipsw"><img alt="IPSW Logo" src="https://github.com/blacktop/ipsw/raw/master/docs/static/images/ipsw.png" height="140" /></a>
  <h1 align="center">ipsw</h1>
  <h4><p align="center">iOS/macOS Research Swiss Army Knife</p></h4>
  <p align="center">
    <a href="https://github.com/blacktop/ipsw/actions?query=workflow%3AGo" alt="Actions">
          <img src="https://github.com/blacktop/ipsw/workflows/Go/badge.svg" /></a>
    <a href="https://github.com/blacktop/ipsw/releases/latest" alt="Downloads">
          <img src="https://img.shields.io/github/downloads/blacktop/ipsw/total.svg" /></a>
    <a href="https://github.com/blacktop/ipsw/releases" alt="GitHub Release">
          <img src="https://img.shields.io/github/release/blacktop/ipsw.svg" /></a>
    <a href="http://doge.mit-license.org" alt="LICENSE">
          <img src="https://img.shields.io/:license-mit-blue.svg" /></a>
</p>
<br>

## What is `ipsw` 🤔

- IPSW downloader/exploder
- OTA downloader/exploder
- macho parser
- ObjC class-dump
- Swift class-dump 🚧
- dyld_shared_cache parser
- kernelcache parser
- img4 parser/decrypter
- device-tree parser
- ARM v8.5-a disassember
- research tool
- otool wannabe
- objdump wannabe
- jtool wannabe

## Install

```bash
❯ brew install blacktop/tap/ipsw
```

## Getting Started

```
❯ ipsw

Download and Parse IPSWs

Usage:
  ipsw [command]

Available Commands:
  device-list     List all iOS devices
  disass          🚧 [WIP] Disassemble ARM binaries at address or symbol
  download        Download and parse IPSW(s) from the internets
  dtree           Parse DeviceTree
  dyld            Parse dyld_shared_cache
  extract         Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW
  help            Help about any command
  iboot           Dump firmwares
  img4            Parse Img4
  info            Display IPSW Info
  kernel          Parse kernelcache
  macho           Parse a MachO file
  ota             Extract file(s) from OTA
  symbolicate     Symbolicate ARM 64-bit crash logs (similar to Apple's symbolicatecrash)
  version         Print the version number of ipsw

Flags:
  -h, --help      help for ipsw
  -V, --verbose   verbose output

Use "ipsw [command] --help" for more information about a command.
```

## Documentation

- [https://blacktop.github.io/ipsw](https://blacktop.github.io/ipsw/docs/)

## Credit

Big shout out to Jonathan Levin's amazing books and his legendary `jtool`

## License

MIT Copyright (c) 2018-2021 **blacktop**
