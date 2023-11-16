---
id: xref
title: xref
hide_title: true
hide_table_of_contents: true
sidebar_label: xref
description: 🚧 [WIP] Find all cross references to an address
---
## ipsw dyld xref

🚧 [WIP] Find all cross references to an address

```
ipsw dyld xref <DSC> <ADDR> [flags]
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
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

