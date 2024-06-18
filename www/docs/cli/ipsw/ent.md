---
id: ent
title: ent
hide_title: true
hide_table_of_contents: true
sidebar_label: ent
description: Search IPSW filesystem DMG or Folder for MachOs with a given entitlement
---
## ipsw ent

Search IPSW filesystem DMG or Folder for MachOs with a given entitlement

```
ipsw ent [flags]
```

### Examples

```bash
# Search IPSW for entitlement key
❯ ipsw ent --ipsw <IPSW> --db /tmp --key platform-application

# Search local folder for entitlement key
❯ ipsw ent --input /usr/bin --db /tmp --val platform-application

# Search IPSW for entitlement value (i.e. one of the <array> strings)
❯ ipsw ent --ipsw <IPSW> --db /tmp --val LockdownMode

# Dump entitlements for MachO in IPSW
❯ ipsw ent --ipsw <IPSW> --db /tmp --file WebContent

# Diff two IPSWs
❯ ipsw ent --diff --ipsw <PREV_IPSW> --ipsw <NEW_IPSW> --db /tmp
```

### Options

```
      --db string           Folder to r/w entitlement databases
  -d, --diff                Diff entitlements
  -f, --file string         Dump entitlements for MachO as plist
      --file-only           Only output the file path of matches
  -h, --help                help for ent
      --input stringArray   Folders of MachOs to analyze
      --ipsw stringArray    IPSWs to analyze
  -k, --key string          Entitlement KEY regex to search for
  -m, --md                  Markdown style output
  -v, --val string          Entitlement VALUE regex to search for (i.e. <array> strings)
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

