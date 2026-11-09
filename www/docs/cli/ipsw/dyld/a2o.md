---
id: a2o
title: a2o
hide_title: true
hide_table_of_contents: true
sidebar_label: a2o
description: Convert address to offset
---
## ipsw dyld a2o

Convert address to offset

```
ipsw dyld a2o <DSC> <ADDR> [flags]
```

### Options

```
  -d, --dec[=true|false]         Return address in decimal
  -h, --help[=true|false]        help for a2o
  -x, --hex[=true|false]         Return address in hexadecimal
      --image-rel[=true|false]   Return offset relative to the containing image __TEXT load address
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

