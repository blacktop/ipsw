---
id: a2f
title: a2f
hide_title: true
hide_table_of_contents: true
sidebar_label: a2f
description: Lookup function containing unslid address
---
## ipsw dyld a2f

Lookup function containing unslid address

```
ipsw dyld a2f <DSC> <ADDR> [flags]
```

### Options

```
  -c, --cache string   Path to .a2s addr to sym cache file (speeds up analysis)
  -h, --help           help for a2f
  -i, --in string      Path to file containing list of addresses to lookup
  -j, --json           Output as JSON
  -o, --out string     Path to output JSON file
  -s, --slide uint     dyld_shared_cache slide to apply
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

