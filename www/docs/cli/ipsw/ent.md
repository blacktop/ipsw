---
id: ent
title: ent
hide_title: true
hide_table_of_contents: true
sidebar_label: ent
description: Search IPSW filesystem DMG for MachOs with a given entitlement
last_update:
  date: 2023-01-13T11:46:22-07:00
  author: blacktop
---
## ipsw ent

Search IPSW filesystem DMG for MachOs with a given entitlement

```
ipsw ent <IPSW> [flags]
```

### Options

```
  -d, --diff            Diff entitlements
  -e, --ent string      Entitlement to search for
  -f, --file string     Dump entitlements for MachO
  -h, --help            help for ent
      --output string   Folder to r/w entitlement databases (default "o")
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

