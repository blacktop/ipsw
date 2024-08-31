---
description: All the MANY files you can extract from local and remote IPSWs/OTAs.
---

# Extract files from IPSWs/OTAs

## **ipsw extract**

Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA *(and MUCH MORE)*

```bash
❯ ipsw extract --help
Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA

Usage:
  ipsw extract <IPSW/OTA | URL> [flags]

Aliases:
  extract, e, ex

Flags:
  -m, --dmg                     Extract File System DMG file
  -t, --dtree                   Extract DeviceTree
  -d, --dyld                    Extract dyld_shared_cache
  -a, --dyld-arch stringArray   dyld_shared_cache architecture to extract
  -f, --files                   Extract File System files
      --flat                    Do NOT perserve directory structure when extracting
  -h, --help                    help for extract
  -i, --iboot                   Extract iBoot
      --insecure                do not verify ssl certs
  -b, --kbag                    Extract Im4p Keybags
  -k, --kernel                  Extract kernelcache
  -o, --output string           Folder to extract files to
      --pattern string          Extract files that match regex
      --proxy string            HTTP/HTTPS proxy
  -r, --remote                  Extract from URL
  -s, --sep                     Extract sep-firmware

Global Flags:
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
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
             --security-opt apparmor:unconfined \
             -v `pwd` :/data \
             blacktop/ipsw -V extract --dyld iPhone11_2_12.4.1_16G102_Restore.ipsw
```

## All these commands can also be ran on remote IPSWs/OTAs

Via the power of `partialzip`

### Extract all files matching a user-specified regex pattern from remote IPSW or OTA zip

```bash
❯ ipsw extract --remote https://updates.cdn-apple.com/../iPodtouch_7_13.3_17C54_Restore.ipsw --pattern '.*BuidManifest.plist$'
```
