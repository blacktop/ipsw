---
id: swift
title: swift
hide_title: true
hide_table_of_contents: true
sidebar_label: swift
description: Dump Swift Optimizations Info
last_update:
  date: 2022-12-23T02:36:33-07:00
  author: blacktop
---
## ipsw dyld swift

Dump Swift Optimizations Info

```
ipsw dyld swift [flags]
```

### Options

```
      --cache string   Path to .a2s addr to sym cache file (speeds up analysis)
  -d, --demangle       Demangle the Swift symbols
  -f, --foreign        Print the foreign type conformances
  -h, --help           help for swift
  -m, --metadata       Print the metadata conformances
  -t, --types          Print the type conformances
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

