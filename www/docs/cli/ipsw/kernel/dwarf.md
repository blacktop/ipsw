---
id: dwarf
title: dwarf
hide_title: true
hide_table_of_contents: true
sidebar_label: dwarf
description: 🚧 Dump DWARF debug information
---
## ipsw kernel dwarf

🚧 Dump DWARF debug information

```
ipsw kernel dwarf <dSYM> [dSYM] [flags]
```

### Examples

```bash
# Dump the task struct
❯ ipsw kernel dwarf -t task /Library/Developer/KDKs/KDK_13.3_22E5230e.kdk/System/Library/Kernels/kernel.development.t6020.dSYM
# Diff task struct
❯ ipsw kernel dwarf --type task --diff
# Diff ALL structs
❯ ipsw kernel dwarf --diff
```

### Options

```
  -d, --diff          Diff two structs
  -h, --help          help for dwarf
  -m, --md            Markdown diff output
  -n, --name string   Name to lookup
  -t, --type string   Type to lookup
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw kernel](/docs/cli/ipsw/kernel)	 - Parse kernelcache

