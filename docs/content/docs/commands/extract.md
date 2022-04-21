---
title: "extract"
date: 2020-01-26T10:58:06-05:00
draft: false
weight: 7
summary: Combine extract commands together.
---

### Extract from IPSW or OTA zip

```bash
❯ ipsw extract --help
Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA

Usage:
  ipsw extract <IPSW/OTA | URL> [flags]

Flags:
  -f, --dmg                     Extract File System DMG
  -t, --dtree                   Extract DeviceTree
  -d, --dyld                    Extract dyld_shared_cache
  -a, --dyld-arch stringArray   dyld_shared_cache architecture to extract
  -h, --help                    help for extract
  -i, --iboot                   Extract iBoot
      --insecure                do not verify ssl certs
  -k, --kernel                  Extract kernelcache
  -o, --output string           Folder to extract files to
      --pattern string          Download remote files that match (not regex)
      --proxy string            HTTP/HTTPS proxy
  -r, --remote                  Extract from URL
  -s, --sep                     Extract sep-firmware

Global Flags:
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### Extract _kernelcache_ from a previously downloaded IPSW or OTA

```bash
❯ ipsw extract --kernel iPhone11,2_12.0_16A366_Restore.ipsw
```

### Extract _dyld_shared_cache_ from a previously downloaded IPSW

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

### Extract all files matching a user-specified regex pattern from remote IPSW or OTA zip

```bash
❯ ipsw extract --remote https://updates.cdn-apple.com/../iPodtouch_7_13.3_17C54_Restore.ipsw --pattern '.*BuidManifest.plist$'
```
