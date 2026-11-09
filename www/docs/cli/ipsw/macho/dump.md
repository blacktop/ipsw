---
id: dump
title: dump
hide_title: true
hide_table_of_contents: true
sidebar_label: dump
description: Dump MachO data at given virtual address
---
## ipsw macho dump

Dump MachO data at given virtual address

```
ipsw macho dump <macho> <address> [flags]
```

### Options

```
  -v, --addr[=true|false]    Output as addresses/uint64s
  -a, --arch string          Which architecture to use for fat/universal MachO
  -b, --bytes[=true|false]   Output as bytes
  -c, --count uint           The number of total items to display
  -e, --entry string         Dump from fileset entry (requires --section)
  -h, --help[=true|false]    help for dump
  -o, --output string        Output to a file
  -x, --section string       Dump a specific segment/section (i.e. __TEXT.__text)
  -g, --segment string       Dump a specific segment (i.e. __TEXT)
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

* [ipsw macho](/docs/cli/ipsw/macho)	 - Parse MachO

