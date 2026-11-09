---
id: dump
title: dump
hide_title: true
hide_table_of_contents: true
sidebar_label: dump
description: Dump data at given virtual address
---
## ipsw dyld dump

Dump data at given virtual address

```
ipsw dyld dump <DSC> <ADDR> [flags]
```

### Options

```
  -a, --addr[=true|false]    Output as addresses/uint64s
  -b, --bytes[=true|false]   Output as bytes
  -c, --count uint           The number of total items to display
  -h, --help[=true|false]    help for dump
  -i, --image string         Dump from image (requires --section)
  -o, --output string        Output to a file
  -x, --section string       Dump a specific segment/section (i.e. __TEXT.__text)
  -s, --size uint            Size of data in bytes
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

