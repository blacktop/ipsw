---
id: dyld
title: dyld
hide_title: true
hide_table_of_contents: true
sidebar_label: dyld
description: Parse dyld_shared_cache
last_update:
  date: 2022-12-23T02:36:33-07:00
  author: blacktop
---
## ipsw dyld

Parse dyld_shared_cache

```
ipsw dyld [flags]
```

### Options

```
  -h, --help   help for dyld
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)
* [ipsw dyld a2f](/docs/cli/ipsw/dyld/a2f)	 - Lookup function containing unslid address
* [ipsw dyld a2o](/docs/cli/ipsw/dyld/a2o)	 - Convert dyld_shared_cache address to offset
* [ipsw dyld a2s](/docs/cli/ipsw/dyld/a2s)	 - Lookup symbol at unslid address
* [ipsw dyld disass](/docs/cli/ipsw/dyld/disass)	 - Disassemble dyld_shared_cache at symbol/vaddr
* [ipsw dyld dump](/docs/cli/ipsw/dyld/dump)	 - Dump dyld_shared_cache data at given virtual address
* [ipsw dyld extract](/docs/cli/ipsw/dyld/extract)	 - Extract dyld_shared_cache from DMG in IPSW
* [ipsw dyld image](/docs/cli/ipsw/dyld/image)	 - Dump image array info
* [ipsw dyld imports](/docs/cli/ipsw/dyld/imports)	 - List all dylibs that load a given dylib
* [ipsw dyld info](/docs/cli/ipsw/dyld/info)	 - Parse dyld_shared_cache
* [ipsw dyld macho](/docs/cli/ipsw/dyld/macho)	 - Parse a dylib file
* [ipsw dyld o2a](/docs/cli/ipsw/dyld/o2a)	 - Convert dyld_shared_cache offset to address
* [ipsw dyld objc](/docs/cli/ipsw/dyld/objc)	 - Dump Objective-C Optimization Info
* [ipsw dyld patches](/docs/cli/ipsw/dyld/patches)	 - Dump dyld patch info
* [ipsw dyld slide](/docs/cli/ipsw/dyld/slide)	 - Dump slide info
* [ipsw dyld split](/docs/cli/ipsw/dyld/split)	 - Extracts all the dyld_shared_cache libraries
* [ipsw dyld str](/docs/cli/ipsw/dyld/str)	 - Search dyld_shared_cache for string
* [ipsw dyld swift](/docs/cli/ipsw/dyld/swift)	 - Dump Swift Optimizations Info
* [ipsw dyld symaddr](/docs/cli/ipsw/dyld/symaddr)	 - Lookup or dump symbol(s)
* [ipsw dyld tbd](/docs/cli/ipsw/dyld/tbd)	 - Generate a .tbd file for a dylib
* [ipsw dyld webkit](/docs/cli/ipsw/dyld/webkit)	 - Get WebKit version from a dyld_shared_cache
* [ipsw dyld xref](/docs/cli/ipsw/dyld/xref)	 - 🚧 [WIP] Find all cross references to an address

