---
id: extract
title: extract
hide_title: true
hide_table_of_contents: true
sidebar_label: extract
description: Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA
last_update:
  date: 2022-12-17T17:42:11-07:00
  author: blacktop
---
## ipsw extract

Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA

```
ipsw extract <IPSW/OTA | URL> [flags]
```

### Options

```
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
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

