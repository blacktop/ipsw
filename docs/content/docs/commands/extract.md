---
title: "extract"
date: 2020-01-26T10:58:06-05:00
draft: false
weight: 7
summary: Combine extract commands together.
---

### Extract _kernelcache_ from a previously downloaded _ipsw_

```bash
❯ ipsw extract --kernel iPhone11,2_12.0_16A366_Restore.ipsw
```

### Extract _dyld_shared_cache_ from a previously downloaded _ipsw_

- `macOS`

```bash
❯ ipsw extract --dyld iPhone11,2_12.0_16A366_Restore.ipsw
   • Extracting dyld_shared_cache from IPSW
   • Mounting DMG
   • Extracting System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e to dyld_shared_cache
   • Unmounting DMG
```

- `docker`

```bash
❯ docker run --init -it --rm \
             --device /dev/fuse \
             --cap-add=SYS_ADMIN \
             -v `pwd` :/data \
             blacktop/ipsw -V extract --dyld iPhone11_2_12.4.1_16G102_Restore.ipsw
```
