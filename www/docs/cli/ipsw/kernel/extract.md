---
id: extract
title: extract
hide_title: true
hide_table_of_contents: true
sidebar_label: extract
description: Extract KEXT(s) from kernelcache
---
## ipsw kernel extract

Extract KEXT(s) from kernelcache

```
ipsw kernel extract <KERNELCACHE> <KEXT> [flags]
```

### Options

```
  -a, --all[=true|false]       Extract all KEXTs
  -e, --arch string            Which architecture to use for fat/universal MachO
      --force[=true|false]     Overwrite existing extracted KEXT(s)
  -h, --help[=true|false]      help for extract
      --imports[=true|false]   Resolve imported symbol names from kernelcache
  -o, --output string          Directory to extract KEXTs to
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw kernel](/docs/cli/ipsw/kernel)	 - Parse kernelcache

