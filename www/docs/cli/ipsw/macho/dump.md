---
id: dump
title: dump
hide_title: true
hide_table_of_contents: true
sidebar_label: dump
description: Dump MachO data at given virtual address
last_update:
  date: 2022-11-28T12:49:26-07:00
  author: blacktop
---
## ipsw macho dump

Dump MachO data at given virtual address

```
ipsw macho dump <macho> <address> [flags]
```

### Options

```
  -v, --addr            Output as addresses/uint64s
  -a, --arch string     Which architecture to use for fat/universal MachO
  -b, --bytes           Output as bytes
  -c, --count uint      The number of total items to display
  -h, --help            help for dump
  -o, --output string   Output to a file
  -s, --size uint       Size of data in bytes
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw macho](/docs/cli/ipsw/macho)	 - Parse MachO

