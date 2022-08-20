---
title: "Roadmap"
date: 2020-01-26T12:51:45-05:00
draft: false
weight: 200
summary: Future features.
---

I'd like to get to a 1-to-1 feature match with `jtool2` _(VERY close now)_

My main goal is to create a mantainable _dyld_shared_cache_ splitter

My strech goal is to make the worlds first _dyld_shared_cache_ disassembler that doesn't take days/a super computer 😏 to analyze

### TODO

- [ ] MachO read/write
- [ ] pure Go dyld splitter
- [ ] APFS/HFS parsing to pull dyld without mounting
- [ ] (jtool) -K Kextract™ a kernel extension by its bundle ID
- [ ] watch for new IPSW files with https://github.com/radovskyb/watcher
- [ ] https://github.com/xerub/img4lib and https://github.com/tihmstar/img4tool
- [ ] devicetree read/write
- [ ] add 💄https://github.com/muesli/termenv
- [ ] maybe use https://github.com/AllenDang/giu for disassembler
- [ ] add https://github.com/mermaid-js/mermaid to docs
- [ ] API maybe use (github.com/minio/simdjson-go)
- [ ] Switch docs to https://squidfunk.github.io/mkdocs-material/getting-started/
- [ ] store download dev session or creds using - https://github.com/keybase/go-keychain
- [ ] speed up downloads w/ https://github.com/ynsgnr/aria2go
- [ ] make a color syntax highlighter like https://github.com/trishume/syntect but for Golang
- [x] use https://github.com/google/gousb to detect what device(s) are connected (maybe filter downloads?)
- [ ] replace cgo sqlite w/ https://pkg.go.dev/modernc.org/sqlite
- [ ] emulator ideas: [qemu](https://github.com/containers/podman/tree/main/pkg/machine/qemu), [qemu](https://github.com/digitalocean/go-qemu), [lxd](https://github.com/lxc/lxd), [qemu-t8030](https://github.com/TrungNguyen1909/qemu-t8030)
