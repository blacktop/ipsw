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
ipsw macho search [flags]
```

### Options

```
  -g, --category string       Search for specific ObjC category regex
  -c, --class string          Search for specific ObjC class regex
  -h, --help                  help for search
  -i, --ipsw string           Path to IPSW to scan for search criteria
      --ivar string           Search for specific ObjC instance variable regex
  -l, --load-command string   Search for specific load command regex
  -p, --protocol string       Search for specific ObjC protocol regex
  -s, --sel string            Search for specific ObjC selector regex
  -m, --sym string            Search for specific symbol regex
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw macho](/docs/cli/ipsw/macho)	 - Parse MachO

