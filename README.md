<p align="center">
  <a href="https://github.com/blacktop/ipsw"><img alt="IPSW Logo" src="https://github.com/blacktop/ipsw/raw/master/docs/static/images/ipsw.png" height="140" /></a>
  <h1 align="center">ipsw</h1>
  <h4><p align="center">iOS/macOS Research Swiss Army Knife</p></h4>
  <p align="center">
    <a href="https://github.com/blacktop/ipsw/actions" alt="Actions">
          <img src="https://github.com/blacktop/ipsw/actions/workflows/go.yml/badge.svg" /></a>
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
- ARM v9-a disassember
- research tool

## Install

```bash
brew install blacktop/tap/ipsw
```

## Getting Started

```
❯ ipsw

Download and Parse IPSWs (and SO much more)

Usage:
  ipsw [command]

Available Commands:
  device-list     List all iOS devices
  download        Download Apple Firmware files (and more)
  dtree           Parse DeviceTree
  dyld            Parse dyld_shared_cache
  ent             Search IPSW filesystem DMG for MachOs with a given entitlement
  extract         Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA
  help            Help about any command
  iboot           Dump firmwares
  idev            USB connected device commands
  img4            Parse Img4
  info            Display IPSW/OTA Info
  kernel          Parse kernelcache
  macho           Parse MachO
  ota             Extract file(s) from OTA
  sepfw           Dump MachOs
  shsh            Get shsh blobs from device
  symbolicate     Symbolicate ARM 64-bit crash logs (similar to Apple's symbolicatecrash)
  update          Download an ipsw update if one exists
  version         Print the version number of ipsw

Flags:
      --config string   config file (default is $HOME/.ipsw.yaml)
  -h, --help            help for ipsw
  -V, --verbose         verbose output

Use "ipsw [command] --help" for more information about a command.
```

## Documentation

- [https://blacktop.github.io/ipsw](https://blacktop.github.io/ipsw/docs/)

## Credit

Big shout out to Jonathan Levin's amazing books and his legendary `jtool`

## License

MIT Copyright (c) 2018-2022 **blacktop**
