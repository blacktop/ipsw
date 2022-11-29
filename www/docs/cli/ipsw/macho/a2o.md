---
id: a2o
title: a2o
hide_title: true
hide_table_of_contents: true
sidebar_label: a2o
description: Convert MachO address to offset
last_update:
  date: 2022-11-29T11:50:35-07:00
  author: blacktop
---
## ipsw macho a2o

Convert MachO address to offset

```
ipsw macho a2o <macho> <vaddr> [flags]
```

### Options

```
  -a, --arch string   Which architecture to use for fat/universal MachO
  -d, --dec           Return address in decimal
  -h, --help          help for a2o
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

