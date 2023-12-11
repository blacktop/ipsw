---
id: patch
title: patch
hide_title: true
hide_table_of_contents: true
sidebar_label: patch
description: Patch MachO Load Commands
---
## ipsw macho patch

Patch MachO Load Commands

```
ipsw macho patch [add|rm|mod] <MACHO> <LC> <LC_FIELDS...> [flags]
```

### Examples

```bash
  # Modify LC_BUILD_VERSION like vtool
  ❯ ipsw macho patch mod MACHO LC_BUILD_VERSION iOS 16.3 16.3 ld 820.1
  # Add an LC_RPATH like install_name_tool
  ❯ ipsw macho patch add MACHO LC_RPATH @executable_path/Frameworks
```

### Options

```
  -h, --help            help for patch
  -o, --output string   Output new file
  -f, --overwrite       Overwrite file
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw macho](/docs/cli/ipsw/macho)	 - Parse MachO

