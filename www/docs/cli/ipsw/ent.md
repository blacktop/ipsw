---
id: ent
title: ent
hide_title: true
hide_table_of_contents: true
sidebar_label: ent
description: Search IPSW filesystem DMG for MachOs with a given entitlement
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
  -m, --md              Markdown style output
  -o, --output string   Folder to r/w entitlement databases
  -v, --val string      Entitlement's value to search for (i.e. <array> strings)
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

