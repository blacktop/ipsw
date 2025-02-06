---
id: a2s
title: a2s
hide_title: true
hide_table_of_contents: true
sidebar_label: a2s
description: Lookup symbol at unslid address
---
## ipsw dyld a2s

Lookup symbol at unslid address

```
ipsw dyld a2s <DSC> <ADDR> [flags]
```

### Options

```
      --cache string   Path to .a2s addr to sym cache file (speeds up analysis)
  -d, --demangle       Demangle symbol names
  -h, --help           help for a2s
  -i, --image          Only lookup address's dyld_shared_cache mapping
  -m, --mapping        Only lookup address's image segment/section
  -s, --slide uint     dyld_shared_cache slide to apply
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

