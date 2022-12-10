---
id: dwarf
title: dwarf
hide_title: true
hide_table_of_contents: true
sidebar_label: dwarf
description: 🚧 Dump DWARF debug information
last_update:
  date: 2022-12-10T00:43:42-07:00
  author: blacktop
---
## ipsw kernel dwarf

🚧 Dump DWARF debug information

```
ipsw kernel dwarf [flags]
```

### Examples

```bash
# Dump the task struct (and pretty print with clang-format)
❯ ipsw kernel dwarf KDK_13.0_22A5342f.kdk/kernel.development.t6000 --type task \
											| clang-format -style='{AlignConsecutiveDeclarations: true}' --assume-filename thread.h
# Diff two versions of a struct
❯ ipsw kernel dwarf --type task --diff KDK_13.0_22A5342f.kdk/kernel.development.t6000 KDK_13.0_22A5352e.kdk/kernel.development.t6000
```

### Options

```
  -d, --diff          Diff two structs
  -h, --help          help for dwarf
  -n, --name string   Name to lookup
  -t, --type string   Type to lookup
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw kernel](/docs/cli/ipsw/kernel)	 - Parse kernelcache

