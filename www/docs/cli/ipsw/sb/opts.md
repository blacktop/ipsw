---
id: opts
title: opts
hide_title: true
hide_table_of_contents: true
sidebar_label: opts
description: List sandbox operations defined in a kernelcache
---
## ipsw sb opts

List sandbox operations defined in a kernelcache

### Synopsis

List all sandbox operation names defined in a kernelcache.

Prints one operation per line. Use --diff to compare operations between two kernelcaches.

Examples:
  # List all operations
  ipsw sb opts kernelcache.release.iPhone18,1

  # Diff operations between two kernelcaches
  ipsw sb opts --diff kernelcache.release.iPhone17,1 kernelcache.release.iPhone18,1

```
ipsw sb opts <KERNELCACHE> [flags]
```

### Options

```
  -d, --diff   Diff two kernel's sandbox operations
  -h, --help   help for opts
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw sb](/docs/cli/ipsw/sb)	 - Sandbox commands

