---
description: All the MANY files you can extract from local and remote IPSWs/OTAs.
---

# Extract files from IPSWs/OTAs

## Device-specific SystemOS images

Some UniversalMac IPSWs contain multiple `Cryptex1,SystemOS` images. Use
`ipsw info` to list their device associations, then select the product type or
board with `--device`. Repeated erase/upgrade identities sharing the same image
are deduplicated; different images require a selection. In a terminal,
`ipsw mount sys` offers an image picker when `--device` is omitted. Scripts
must supply `--device` when the SystemOS image is ambiguous.

```shell
ipsw mount sys UniversalMac.ipsw --device Mac18,5
ipsw extract UniversalMac.ipsw --dmg sys --device Mac18,5
ipsw extract UniversalMac.ipsw --dyld --device j873gap --dyld-arch arm64e_x1
ipsw diff old.ipsw new.ipsw --device Mac18,5
```

The same selector applies to remote IPSW DMG/cache extraction and to `extract
--files` and `--fcs-key`. `--ident` continues to select the RestoreRamDisk install
variant; it can be combined with `--device`.

For `download ipsw`, `--device` filters the firmware feed. Use
`--extract-device` to select a product or board inside a universal IPSW without
changing that feed query:

```shell
ipsw download ipsw --macos --version 27.0 --dyld --extract-device Mac18,5
```

Without `--extract-device`, partial downloads continue to use `--device` as
the extraction selector.

IPSW scans also accept `--device`: `macho search`, `dsc imports --ipsw`,
`ent --fs`, `symbols`, `launchd`, `sb diff`, and the IPSW sources in `sb reach`.
`ota patch rsr --device` selects the manifest's DMG names; use `--dyld-arch`
to restrict which architecture's cryptex patches are processed.

```shell
ipsw macho search UniversalMac.ipsw --sym 'example' --device Mac18,5
ipsw ent --fs UniversalMac.ipsw --device j873gap
ipsw symbols UniversalMac.ipsw --filesystem --device Mac18,5
```

The selector is for IPSW input, not folder or standalone DSC input. Entitlement
database ingestion scans all SystemOS variants into one firmware result.
When there are multiple images, their executable paths are prefixed with
`SystemOS/<image-name>/` to preserve entries that differ between variants.
Use `ent --fs --device` for a selected-device scan.

The macOS 27.0 build 26A428 SystemOS for Mac18,5 contains
`dyld_shared_cache_arm64e_x1`, with cache magic `dyld_v1arm64ex1`. Use the exact
architecture spelling `arm64e_x1`; `arm64e` selects the separate generic cache.
A cache name/subtype alone does not describe the variant's instruction-set or
ABI requirements.

For IPSW diffs, `--device` selects the target's DMGs and kernelcache on both
sides. If one input predates the target, it can be used as a comparison baseline
only when it has one SystemOS image and one distinct, valid kernelcache path.
An input with device-specific kernels requires a target present in that input.
Default report titles include the
selected device so reports for different targets have distinct filenames.
It does not filter the raw ZIP
firmware/file inventory, and it is not an OTA/directory diff option.

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
