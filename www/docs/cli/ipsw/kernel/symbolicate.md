---
id: symbolicate
title: symbolicate
hide_title: true
hide_table_of_contents: true
sidebar_label: symbolicate
description: Symbolicate kernelcache
---
## ipsw kernel symbolicate

Symbolicate kernelcache

```
ipsw kernel symbolicate [flags]
```

### Options

```
  -a, --arch string         Which architecture to use for fat/universal MachO
  -f, --flat                Output results in flat file '.syms' format
  -h, --help                help for symbolicate
  -j, --json                Output results in JSON format
  -l, --lookup uint         Lookup a symbol by address
  -o, --output string       Folder to write files to
  -q, --quiet               Do NOT display logging
  -s, --signatures string   Path to signatures folder
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw kernel](/docs/cli/ipsw/kernel)	 - Parse kernelcache

