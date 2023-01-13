---
id: lipo
title: lipo
hide_title: true
hide_table_of_contents: true
sidebar_label: lipo
description: Extract single MachO out of a universal/fat MachO
last_update:
  date: 2023-01-13T11:46:22-07:00
  author: blacktop
---
## ipsw macho lipo

Extract single MachO out of a universal/fat MachO

```
ipsw macho lipo [flags]
```

### Options

```
  -a, --arch string     Which architecture to use for fat/universal MachO
  -h, --help            help for lipo
      --output string   Directory to extract the MachO
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw macho](/docs/cli/ipsw/macho)	 - Parse MachO

