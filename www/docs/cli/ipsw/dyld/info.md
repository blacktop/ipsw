---
id: info
title: info
hide_title: true
hide_table_of_contents: true
sidebar_label: info
description: Parse dyld_shared_cache
---
## ipsw dyld info

Parse dyld_shared_cache

### Synopsis

Parse a dyld_shared_cache. Use --dylibs with either --diff or --delta and
two caches to compare images from the first cache to the second. The comparison
modes are mutually exclusive. With --json, either mode emits sorted added,
removed, and changed image records with versions; an empty version means the
image has no source-version load command.

```
ipsw dyld info <DSC> [DSC] [flags]
```

### Examples

```bash
  ipsw dyld info --dylibs --delta old/DSC new/DSC
  ipsw dyld info --dylibs --diff --json old/DSC new/DSC
```

### Options

```
  -c, --closures   Dump program launch closures
      --delta      Compare two DSCs' image versions (requires --dylibs)
      --diff       Diff two DSCs' images (requires --dylibs)
  -d, --dlopen     Dump all dylibs and bundles with dlopen closures
  -l, --dylibs     List dylibs and their versions
  -h, --help       help for info
  -j, --json       Output as JSON
  -s, --sig        Print code signature
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

