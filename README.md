<p align="center">
  <a href="https://github.com/blacktop/ipsw"><img alt="IPSW Logo" src="https://github.com/blacktop/ipsw/raw/master/docs/static/images/ipsw.png" height="140" /></a>
  <h1 align="center">ipsw</h1>
  <h4><p align="center">Download and parse iOS ipsw(s)</p></h4>
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

> **NOTE:** for version that doesn't require `lzfse` or `capstone` use the one without **extras** in the [releases](https://github.com/blacktop/ipsw/releases/latest)

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
  device-list List all iOS devices
  download    Download and parse IPSW(s) from the internets
  dtree       Parse DeviceTree
  dyld        Parse dyld_shared_cache
  help        Help about any command
  info        Display IPSW Info
  kernel      Parse kernelcache
  macho       Parse a MachO file
  version     Print the version number of ipsw

Flags:
  -h, --help      help for ipsw
  -V, --verbose   verbose output

Use "ipsw [command] --help" for more information about a command.
```

## Documentation

### See here [Docs](https://blacktop.github.io/ipsw/)

## TODO

- [x] use https://github.com/gocolly/colly
- [x] parse plists for folder creation
- [ ] create offline copy of ipsw.me API
- [ ] https://github.com/xerub/img4lib
- [ ] devicetree read/write
- [ ] add 💄https://github.com/muesli/termenv
- [ ] maybe use https://github.com/AllenDang/giu for disassembler

## Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/blacktop/ipsw/issues/new)

## License

MIT Copyright (c) 2018 **blacktop**
