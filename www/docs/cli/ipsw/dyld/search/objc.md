---
id: objc
title: objc
hide_title: true
hide_table_of_contents: true
sidebar_label: objc
description: Find Dylib files for given ObjC search criteria
---
## ipsw dyld search objc

Find Dylib files for given ObjC search criteria

```
ipsw dyld search objc <DSC> [flags]
```

### Options

```
  -g, --category string   Search for specific ObjC category regex
  -c, --class string      Search for specific ObjC class regex
  -h, --help              help for objc
  -i, --image strings     Images to search (default: all)
      --ivar string       Search for specific ObjC instance variable regex
  -p, --protocol string   Search for specific ObjC protocol regex
  -s, --sel string        Search for specific ObjC selector regex
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld search](/docs/cli/ipsw/dyld/search)	 - Find Dylib files for given search criteria

