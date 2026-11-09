---
id: ibootim
title: ibootim
hide_title: true
hide_table_of_contents: true
sidebar_label: ibootim
description: Dump iBoot Images
---
## ipsw fw ibootim

Dump iBoot Images

### Synopsis

Extract iBoot images from an IPSW, URL (with --remote), IM4P, or raw iBoot image.

```
ipsw fw ibootim <IPSW|URL|IM4P|IBOOTIM> [flags]
```

### Options

```
  -f, --flat[=true|false]     Do NOT preserve directory structure when extracting im4p files
  -h, --help[=true|false]     help for ibootim
  -i, --info[=true|false]     Print info
  -o, --output string         Folder to extract files to
  -r, --remote[=true|false]   Parse remote IPSW URL
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

