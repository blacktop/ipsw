---
id: mod
title: mod
hide_title: true
hide_table_of_contents: true
sidebar_label: mod
description: Modify a load command to a MachO file
---
## ipsw macho patch mod

Modify a load command to a MachO file

```
ipsw macho patch mod <MACHO> <LC> <LC_FIELDS...> [flags]
```

### Examples

```bash
# Modify LC_BUILD_VERSION like vtool
❯ ipsw macho patch mod MACHO LC_BUILD_VERSION iOS 16.3 16.3 ld 820.1
```

### Options

```
  -h, --help[=true|false]        help for mod
  -o, --output string            Output new file
  -f, --overwrite[=true|false]   Overwrite file
  -s, --re-sign[=true|false]     Adhoc sign file
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw macho patch](/docs/cli/ipsw/macho/patch)	 - Patch MachO Load Commands

