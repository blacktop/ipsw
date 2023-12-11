---
id: search
title: search
hide_title: true
hide_table_of_contents: true
sidebar_label: search
description: Find Dylib files for given search criteria
---
## ipsw dyld search

Find Dylib files for given search criteria

```
ipsw dyld search <DSC> [flags]
```

### Options

```
  -h, --help                  help for search
  -l, --load-command string   Search for specific load command regex
  -x, --section string        Search for specific section regex
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache
* [ipsw dyld search objc](/docs/cli/ipsw/dyld/search/objc)	 - Find Dylib files for given ObjC search criteria
* [ipsw dyld search swift](/docs/cli/ipsw/dyld/search/swift)	 - Find Dylib files for given Swift search criteria

