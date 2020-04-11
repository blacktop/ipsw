---
title: "Roadmap"
date: 2020-01-26T12:51:45-05:00
draft: false
weight: 100
summary: Future features.
---

I'd eventually like to get to a 1-to-1 feature match with `jtool2`.

My main goal is to create a mantainable _dyld_shared_cache_ splitter

### TODO

- [x] use https://github.com/gocolly/colly
- [x] parse plists for folder creation
- [ ] MachO read/write
- [ ] pure Go dyld splitter
- [x] pure Go lzfse _(thanks to [aixiansheng/lzfse](https://github.com/aixiansheng/lzfse))_
- [x] OTA support
- [ ] APFS/HFS parsing to pull dyld without mounting
- [ ] watch for new IPSW files with https://github.com/radovskyb/watcher
- [ ] https://github.com/xerub/img4lib and https://github.com/tihmstar/img4tool
- [ ] devicetree read/write
- [ ] add 💄https://github.com/muesli/termenv
- [ ] maybe use https://github.com/AllenDang/giu for disassembler
- [ ] add https://github.com/mermaid-js/mermaid to docs
- [ ] API maybe use (github.com/minio/simdjson-go)
