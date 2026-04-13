---
id: list
title: list
hide_title: true
hide_table_of_contents: true
sidebar_label: list
description: List sandbox profile names in a kernelcache
---
## ipsw sb list

List sandbox profile names in a kernelcache

### Synopsis

List all sandbox profile names found in a kernelcache or pre-extracted blob.

Prints one profile name per line, suitable for scripting.

Examples:
  # List all profiles in a kernelcache
  ipsw sb list kernelcache.release.iPhone18,1

  # List profiles from a pre-extracted collection blob
  ipsw sb list -i sandbox_collection.bin -o operations.txt --darwin-version 25.0.0

  # List protobox profiles
  ipsw sb list kernelcache.release.iPhone18,1 --type protobox

```
ipsw sb list [KERNELCACHE] [flags]
```

### Options

```
      --darwin-version string   Darwin version (required when operations list is provided without kernelcache)
  -h, --help                    help for list
  -i, --input string            Input sandbox profile binary file
  -o, --operations string       Input operations list file (one operation per line)
      --type string             Sandbox source type: collection, protobox, or profile (default "collection")
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

