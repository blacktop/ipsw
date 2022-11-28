---
description: All the MANY files you can extract from local and remote IPSWs/OTAs.
---

# Extract files from IPSWs/OTAs

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
