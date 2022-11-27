---
id: o2a
title: o2a
hide_title: true
hide_table_of_contents: true
sidebar_label: o2a
description: Convert MachO offset to address
last_update:
  date: 2022-11-26T17:36:57-07:00
  author: blacktop
---
## ipsw macho o2a

Convert MachO offset to address

```
ipsw macho o2a <macho> <offset> [flags]
```

### Options

```
  -a, --arch string   Which architecture to use for fat/universal MachO
  -d, --dec           Return address in decimal
  -h, --help          help for o2a
  -x, --hex           Return address in hexadecimal
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw macho](/docs/cli/ipsw/macho)	 - Parse MachO

