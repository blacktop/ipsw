---
date: 2022-11-20T23:11:40-07:00
title: "ipsw dyld xref"
slug: ipsw_dyld_xref
url: /commands/ipsw_dyld_xref/
---
## ipsw dyld xref

🚧 [WIP] Find all cross references to an address

```
ipsw dyld xref <dyld_shared_cache> <vaddr> [flags]
```

### Options

```
  -a, --all            Search all images
      --cache string   Path to .a2s addr to sym cache file (speeds up analysis)
  -h, --help           help for xref
  -i, --image string   Dylib image to search
      --imports        Search all other dylibs that import the dylib containing the xref src
  -s, --slide uint     dyld_shared_cache slide to apply (not supported yet)
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/cmd/ipsw_dyld/)	 - Parse dyld_shared_cache

