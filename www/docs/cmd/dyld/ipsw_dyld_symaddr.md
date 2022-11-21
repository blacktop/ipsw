---
date: 2022-11-20T23:11:40-07:00
title: "ipsw dyld symaddr"
slug: ipsw_dyld_symaddr
url: /commands/ipsw_dyld_symaddr/
---
## ipsw dyld symaddr

Lookup or dump symbol(s)

```
ipsw dyld symaddr <dyld_shared_cache> [flags]
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
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/cmd/ipsw_dyld/)	 - Parse dyld_shared_cache

