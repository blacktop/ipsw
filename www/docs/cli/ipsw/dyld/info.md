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
  -c, --closures[=true|false]   Dump program launch closures
      --delta[=true|false]      Compare two DSCs' image versions (requires --dylibs)
      --diff[=true|false]       Diff two DSCs' images (requires --dylibs)
  -d, --dlopen[=true|false]     Dump all dylibs and bundles with dlopen closures
  -l, --dylibs[=true|false]     List dylibs and their versions
  -h, --help[=true|false]       help for info
  -j, --json[=true|false]       Output as JSON
  -s, --sig[=true|false]        Print code signature
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

