---
date: 2022-11-20T23:11:40-07:00
title: "ipsw dyld info"
slug: ipsw_dyld_info
url: /commands/ipsw_dyld_info/
---
## ipsw dyld info

Parse dyld_shared_cache

```
ipsw dyld info <dyld_shared_cache> [flags]
```

### Options

```
  -c, --closures   Dump program launch closures
      --diff       Diff two DSC's images
  -d, --dlopen     Dump all dylibs and bundles with dlopen closures
  -l, --dylibs     List dylibs and their versions
  -h, --help       help for info
  -j, --json       Output as JSON
  -s, --sig        Print code signature
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/cmd/ipsw_dyld/)	 - Parse dyld_shared_cache

