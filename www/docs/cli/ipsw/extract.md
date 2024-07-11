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

```
ipsw extract <IPSW/OTA | URL> [flags]
```

### Options

```
      --device string           Device to extract kernel for (e.g. iPhone10,6)
      --dmg string              Extract DMG file (app, sys, fs)
      --driverkit               Extract DriverKit dyld_shared_cache
      --dtree                   Extract DeviceTree
  -d, --dyld                    Extract dyld_shared_cache
  -a, --dyld-arch stringArray   dyld_shared_cache architecture to extract
  -x, --exclave                 Extract Exclave Bundle
      --fcs-key                 Extract AEA1 DMG fcs-key pem files
  -f, --files                   Extract File System files
      --flat                    Do NOT perserve directory structure when extracting
  -h, --help                    help for extract
      --iboot                   Extract iBoot
      --insecure                do not verify ssl certs
  -j, --json                    Output extracted paths as JSON
      --kbag                    Extract Im4p Keybags
  -k, --kernel                  Extract kernelcache
  -o, --output string           Folder to extract files to
  -p, --pattern string          Extract files that match regex
      --pem-db string           AEA pem DB JSON file
      --proxy string            HTTP/HTTPS proxy
  -r, --remote                  Extract from URL
      --sep                     Extract sep-firmware
      --sptm                    Extract SPTM and TXM Firmwares
      --sys-ver                 Extract SystemVersion
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

