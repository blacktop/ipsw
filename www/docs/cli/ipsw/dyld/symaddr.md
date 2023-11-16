---
id: symaddr
title: symaddr
hide_title: true
hide_table_of_contents: true
sidebar_label: symaddr
description: Lookup or dump symbol(s)
---
## ipsw dyld symaddr

Lookup or dump symbol(s)

```
ipsw dyld symaddr <DSC> [flags]
```

### Options

```
  -a, --all            Find all symbol matches
  -b, --binds          Also search LC_DYLD_INFO binds
  -h, --help           help for symaddr
  -i, --image string   dylib image to search
      --in string      Path to JSON file containing list of symbols to lookup
      --out string     Path to output JSON file
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

