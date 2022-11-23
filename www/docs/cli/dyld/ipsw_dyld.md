---
id: ipsw_dyld
title: ipsw dyld
hide_title: true
sidebar_label: dyld
description: Parse dyld_shared_cache
last_update:
  date: 2022-11-23T16:33:46-07:00
  author: blacktop
---
# ipsw dyld

Parse dyld_shared_cache

```
ipsw dyld [flags]
```

## Options

```
  -h, --help   help for dyld
```

## Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

## See also

* [ipsw](/docs/cli/dyld/ipsw)	 - Download and Parse IPSWs (and SO much more)
* [ipsw dyld a2f](/docs/cli/dyld/ipsw_dyld_a2f)	 - Lookup function containing unslid address
* [ipsw dyld a2o](/docs/cli/dyld/ipsw_dyld_a2o)	 - Convert dyld_shared_cache address to offset
* [ipsw dyld a2s](/docs/cli/dyld/ipsw_dyld_a2s)	 - Lookup symbol at unslid address
* [ipsw dyld disass](/docs/cli/dyld/ipsw_dyld_disass)	 - Disassemble dyld_shared_cache at symbol/vaddr
* [ipsw dyld dump](/docs/cli/dyld/ipsw_dyld_dump)	 - Dump dyld_shared_cache data at given virtual address
* [ipsw dyld extract](/docs/cli/dyld/ipsw_dyld_extract)	 - Extract dyld_shared_cache from DMG in IPSW
* [ipsw dyld image](/docs/cli/dyld/ipsw_dyld_image)	 - Dump image array info
* [ipsw dyld imports](/docs/cli/dyld/ipsw_dyld_imports)	 - List all dylibs that load a given dylib
* [ipsw dyld info](/docs/cli/dyld/ipsw_dyld_info)	 - Parse dyld_shared_cache
* [ipsw dyld macho](/docs/cli/dyld/ipsw_dyld_macho)	 - Parse a dylib file
* [ipsw dyld o2a](/docs/cli/dyld/ipsw_dyld_o2a)	 - Convert dyld_shared_cache offset to address
* [ipsw dyld objc](/docs/cli/dyld/ipsw_dyld_objc)	 - Dump Objective-C Optimization Info
* [ipsw dyld patches](/docs/cli/dyld/ipsw_dyld_patches)	 - Dump dyld patch info
* [ipsw dyld slide](/docs/cli/dyld/ipsw_dyld_slide)	 - Dump slide info
* [ipsw dyld split](/docs/cli/dyld/ipsw_dyld_split)	 - Extracts all the dyld_shared_cache libraries
* [ipsw dyld str](/docs/cli/dyld/ipsw_dyld_str)	 - Search dyld_shared_cache for string
* [ipsw dyld symaddr](/docs/cli/dyld/ipsw_dyld_symaddr)	 - Lookup or dump symbol(s)
* [ipsw dyld tbd](/docs/cli/dyld/ipsw_dyld_tbd)	 - Generate a .tbd file for a dylib
* [ipsw dyld webkit](/docs/cli/dyld/ipsw_dyld_webkit)	 - Get WebKit version from a dyld_shared_cache
* [ipsw dyld xref](/docs/cli/dyld/ipsw_dyld_xref)	 - 🚧 [WIP] Find all cross references to an address

