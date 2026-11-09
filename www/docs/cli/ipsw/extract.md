---
id: extract
title: extract
hide_title: true
hide_table_of_contents: true
sidebar_label: extract
description: Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA
---
## ipsw extract

Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA

### Synopsis

Extract components from an IPSW or OTA. --json keeps the legacy per-component
output. Add --json-format artifacts for one schema-versioned document containing
an artifacts array (kind, path, and optional devices), optional keybags and
system_version metadata, and a complete flag. An extraction failure retains
completed artifacts, sets complete to false, includes an error, and exits nonzero.

```
ipsw extract <IPSW/OTA | URL> [flags]
```

### Examples

```bash
# Extract kernelcache from IPSW
$ ipsw extract --kernel iPhone15,2_16.5_20F66_Restore.ipsw

# Extract dyld_shared_cache for specific architecture
$ ipsw extract --dyld --dyld-arch arm64e iPhone.ipsw

# Extract all files matching a pattern (from the IPSW zip contents)
$ ipsw extract --pattern '.*\.ttf$' iOS.ipsw

# Extract multiple components with custom output directory
$ ipsw extract --kernel --sep --dyld -o /tmp/extracted iPhone.ipsw

# Emit one versioned JSON document for all extracted components
$ ipsw extract --kernel --sep --json --json-format artifacts iPhone.ipsw

# Extract from remote URL
$ ipsw extract --kernel --remote https://updates.cdn-apple.com/iPhone.ipsw

# Extract system version info as JSON
$ ipsw extract --sys-ver iPhone.ipsw

# Extract files from filesystem DMG matching pattern
$ ipsw extract --files --pattern '.*LaunchDaemons.*\.plist$' iPhone.ipsw

# Extract DriverKit dyld_shared_cache
$ ipsw extract --dyld --driverkit macOS.ipsw

```

### Options

```
      --device string            Device to select kernel/DMGs/caches for (product type or DMG board, e.g. Mac18,5)
      --dmg string               Extract DMG file (app, sys, fs, exc, rdisk, rosetta)
      --driverkit[=true|false]   Extract DriverKit dyld_shared_cache
      --dtree[=true|false]       Extract DeviceTree
  -d, --dyld[=true|false]        Extract dyld_shared_cache
  -a, --dyld-arch stringArray    dyld_shared_cache architecture to extract
  -x, --exclave[=true|false]     Extract Exclave Bundle
      --fcs-key[=true|false]     Extract AEA1 keys for SystemOS DMGs (legacy filesystem fallback)
  -f, --files[=true|false]       Extract File System files
      --flat[=true|false]        Do NOT preserve directory structure when extracting
  -h, --help[=true|false]        help for extract
      --iboot[=true|false]       Extract iBoot
      --ident string             Identity Variant to select specific RestoreRamDisk (e.g. 'Erase', 'Upgrade', 'Recovery')
      --insecure[=true|false]    do not verify ssl certs
  -j, --json[=true|false]        Output extracted paths as JSON
      --json-format string       JSON format: legacy (per component) or artifacts (one versioned report; requires --json) (default "legacy")
      --kbag[=true|false]        Extract Im4p Keybags
  -k, --kernel[=true|false]      Extract kernelcache
  -l, --lookup[=true|false]      Lookup decryption keys on theapplewiki.com
  -o, --output string            Folder to extract files to
  -p, --pattern string           Extract files that match regex
      --pem-db string            AEA pem DB JSON file
      --proxy string             HTTP/HTTPS proxy
  -r, --remote[=true|false]      Extract from URL
      --sep[=true|false]         Extract sep-firmware
      --sptm[=true|false]        Extract SPTM and TXM Firmwares
      --sys-ver[=true|false]     Extract SystemVersion
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

