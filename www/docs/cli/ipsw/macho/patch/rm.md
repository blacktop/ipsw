---
id: rm
title: rm
hide_title: true
hide_table_of_contents: true
sidebar_label: rm
description: Remove a load command to a MachO file
---
## ipsw macho patch rm

Remove a load command to a MachO file

```
ipsw macho patch rm <MACHO> <LC> <LC_FIELDS...> [flags]
```

### Examples

```bash
# Remove an LC_RPATH like install_name_tool
❯ ipsw macho patch rm MACHO LC_RPATH @executable_path/Frameworks
```

### Options

```
  -h, --help            help for rm
  -o, --output string   Output new file
  -f, --overwrite       Overwrite file
  -s, --re-sign         Adhoc sign file
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw macho patch](/docs/cli/ipsw/macho/patch)	 - Patch MachO Load Commands

