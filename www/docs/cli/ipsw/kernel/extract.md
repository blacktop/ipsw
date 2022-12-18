---
id: extract
title: extract
hide_title: true
hide_table_of_contents: true
sidebar_label: extract
description: Extract KEXT(s) from kernelcache
last_update:
  date: 2022-12-17T17:42:11-07:00
  author: blacktop
---
## ipsw kernel extract

Extract KEXT(s) from kernelcache

```
ipsw kernel extract <KERNELCACHE> <KEXT> [flags]
```

### Options

```
  -a, --all             Extract all KEXTs
  -h, --help            help for extract
      --output string   Directory to extract KEXTs to
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw kernel](/docs/cli/ipsw/kernel)	 - Parse kernelcache

