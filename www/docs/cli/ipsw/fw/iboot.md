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
ipsw fw iboot <IPSW|URL|IM4P|PAYLOAD> [flags]
```

### Options

```
  -f, --flat[=true|false]      Do NOT preserve directory structure when extracting im4p files
  -h, --help[=true|false]      help for iboot
  -m, --min int                Minimum length of string to print (default 5)
  -o, --output string          Folder to extract files to
  -r, --remote[=true|false]    Parse remote IPSW URL
  -s, --strings[=true|false]   Print strings
      --version[=true|false]   Print version
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw fw](/docs/cli/ipsw/fw)	 - Firmware commands

