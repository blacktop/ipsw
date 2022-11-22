---
id: ipsw_macho_a2o
title: ipsw macho a2o
hide_title: true
sidebar_label: a2o
description: Convert MachO address to offset
last_update:
  date: 2022-11-21T19:10:35-07:00
  author: blacktop
---
# ipsw macho a2o

Convert MachO address to offset

```
ipsw macho a2o <macho> <vaddr> [flags]
```

## Options

```
  -a, --arch string   Which architecture to use for fat/universal MachO
  -d, --dec           Return address in decimal
  -h, --help          help for a2o
  -x, --hex           Return address in hexadecimal
```

## Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

## See also

* [ipsw macho](/docs/cli/macho/ipsw_macho)	 - Parse MachO

