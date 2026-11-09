---
id: a2o
title: a2o
hide_title: true
hide_table_of_contents: true
sidebar_label: a2o
description: Convert MachO address to offset
---
## ipsw macho a2o

Convert MachO address to offset

```
ipsw macho a2o <macho> <vaddr> [flags]
```

### Options

```
  -a, --arch string         Which architecture to use for fat/universal MachO
  -d, --dec[=true|false]    Return address in decimal
  -h, --help[=true|false]   help for a2o
  -x, --hex[=true|false]    Return address in hexadecimal
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

