---
id: iboot
title: iboot
hide_title: true
hide_table_of_contents: true
sidebar_label: iboot
description: Dump iBoot files
---
## ipsw fw iboot

Dump iBoot files

```
ipsw fw iboot <IPSW|URL|IM4P> [flags]
```

### Options

```
  -f, --flat            Do NOT preserve directory structure when extracting im4p files
  -h, --help            help for iboot
  -m, --min int         Minimum length of string to print (default 5)
  -o, --output string   Folder to extract files to
  -r, --remote          Parse remote IPSW URL
  -s, --strings         Print strings
      --version         Print version
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw fw](/docs/cli/ipsw/fw)	 - Firmware commands

