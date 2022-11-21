---
date: 2022-11-20T23:11:40-07:00
title: "ipsw dyld"
slug: ipsw_dyld
url: /commands/ipsw_dyld/
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
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/cmd/ipsw/)	 - Download and Parse IPSWs (and SO much more)
* [ipsw dyld a2f](/cmd/ipsw_dyld_a2f/)	 - Lookup function containing unslid address
* [ipsw dyld a2o](/cmd/ipsw_dyld_a2o/)	 - Convert dyld_shared_cache address to offset
* [ipsw dyld a2s](/cmd/ipsw_dyld_a2s/)	 - Lookup symbol at unslid address
* [ipsw dyld disass](/cmd/ipsw_dyld_disass/)	 - Disassemble dyld_shared_cache at symbol/vaddr
* [ipsw dyld dump](/cmd/ipsw_dyld_dump/)	 - Dump dyld_shared_cache data at given virtual address
* [ipsw dyld extract](/cmd/ipsw_dyld_extract/)	 - Extract dyld_shared_cache from DMG in IPSW
* [ipsw dyld image](/cmd/ipsw_dyld_image/)	 - Dump image array info
* [ipsw dyld imports](/cmd/ipsw_dyld_imports/)	 - List all dylibs that load a given dylib
* [ipsw dyld info](/cmd/ipsw_dyld_info/)	 - Parse dyld_shared_cache
* [ipsw dyld macho](/cmd/ipsw_dyld_macho/)	 - Parse a dylib file
* [ipsw dyld o2a](/cmd/ipsw_dyld_o2a/)	 - Convert dyld_shared_cache offset to address
* [ipsw dyld objc](/cmd/ipsw_dyld_objc/)	 - Dump Objective-C Optimization Info
* [ipsw dyld patches](/cmd/ipsw_dyld_patches/)	 - Dump dyld patch info
* [ipsw dyld slide](/cmd/ipsw_dyld_slide/)	 - Dump slide info
* [ipsw dyld split](/cmd/ipsw_dyld_split/)	 - Extracts all the dyld_shared_cache libraries
* [ipsw dyld str](/cmd/ipsw_dyld_str/)	 - Search dyld_shared_cache for string
* [ipsw dyld symaddr](/cmd/ipsw_dyld_symaddr/)	 - Lookup or dump symbol(s)
* [ipsw dyld tbd](/cmd/ipsw_dyld_tbd/)	 - Generate a .tbd file for a dylib
* [ipsw dyld webkit](/cmd/ipsw_dyld_webkit/)	 - Get WebKit version from a dyld_shared_cache
* [ipsw dyld xref](/cmd/ipsw_dyld_xref/)	 - 🚧 [WIP] Find all cross references to an address

