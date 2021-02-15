---
title: "Roadmap"
date: 2020-01-26T12:51:45-05:00
draft: false
weight: 200
summary: Future features.
---

I'd eventually like to get to a 1-to-1 feature match with `jtool2`.

My main goal is to create a mantainable _dyld_shared_cache_ splitter

### TODO

- [ ] Impliment a symbolicate for crashlogs by implimenting (`/Applications/Xcode.app/Contents/SharedFrameworks/DVTFoundation.framework/Versions/A/Resources/symbolicatecrash`)
- [ ] MachO read/write
- [ ] pure Go dyld splitter
- [ ] fix OTA support for iOS 14.x (dyld_shared_cache extraction broke)
- [ ] APFS/HFS parsing to pull dyld without mounting
- [ ] watch for new IPSW files with https://github.com/radovskyb/watcher
- [ ] https://github.com/xerub/img4lib and https://github.com/tihmstar/img4tool
- [ ] devicetree read/write
- [ ] add 💄https://github.com/muesli/termenv
- [ ] maybe use https://github.com/AllenDang/giu for disassembler
- [ ] add https://github.com/mermaid-js/mermaid to docs
- [ ] API maybe use (github.com/minio/simdjson-go)
