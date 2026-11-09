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
      --all[=true|false]       Dump all types
  -d, --diff[=true|false]      Diff two structs
      --enums[=true|false]     Dump all enums
  -h, --help[=true|false]      help for dwarf
  -m, --md[=true|false]        Markdown diff output
  -n, --name string            Name to lookup
      --no-off[=true|false]    Do NOT display struct field offsets in output
      --structs[=true|false]   Dump all structs
  -t, --type string            Type to lookup
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

