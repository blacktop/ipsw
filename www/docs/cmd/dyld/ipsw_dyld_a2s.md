---
date: 2022-11-20T23:11:40-07:00
title: "ipsw dyld a2s"
slug: ipsw_dyld_a2s
url: /commands/ipsw_dyld_a2s/
---
## ipsw dyld a2s

Lookup symbol at unslid address

```
ipsw dyld a2s <dyld_shared_cache> <vaddr> [flags]
```

### Options

```
      --cache string   Path to .a2s addr to sym cache file (speeds up analysis)
  -h, --help           help for a2s
  -i, --image          Only lookup address's dyld_shared_cache mapping
  -m, --mapping        Only lookup address's image segment/section
  -s, --slide uint     dyld_shared_cache slide to apply
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/cmd/ipsw_dyld/)	 - Parse dyld_shared_cache

