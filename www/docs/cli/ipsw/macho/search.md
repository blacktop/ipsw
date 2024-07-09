---
id: search
title: search
hide_title: true
hide_table_of_contents: true
sidebar_label: search
description: Find Mach-O files for given search criteria
---
## ipsw macho search

Find Mach-O files for given search criteria

```
ipsw macho search <IPSW> [flags]
```

### Options

```
  -g, --category string       Search for specific ObjC category regex
  -c, --class string          Search for specific ObjC class regex
  -h, --help                  help for search
  -i, --import string         Search for specific import regex
  -r, --ivar string           Search for specific ObjC instance variable regex
  -t, --launch-const string   Search for launch constraint regex
  -l, --load-command string   Search for specific load command regex
      --pem-db string         AEA pem DB JSON file
  -p, --protocol string       Search for specific ObjC protocol regex
  -x, --section string        Search for specific section regex
  -s, --sel string            Search for specific ObjC selector regex
  -m, --sym string            Search for specific symbol regex
  -u, --uuid string           Search for MachO by UUID
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

