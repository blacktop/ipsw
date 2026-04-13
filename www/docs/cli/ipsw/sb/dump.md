---
id: dump
title: dump
hide_title: true
hide_table_of_contents: true
sidebar_label: dump
description: Dump raw sandbox binary blobs from a kernelcache
---
## ipsw sb dump

Dump raw sandbox binary blobs from a kernelcache

### Synopsis

Extract raw sandbox binary blobs (collection, profile, protobox) from a
kernelcache and write them next to the input file.

These blobs can be used as input to other sandbox commands via the -i flag.

Examples:
  ipsw sb dump kernelcache.release.iPhone18,1

```
ipsw sb dump <KERNELCACHE> [flags]
```

### Options

```
  -h, --help   help for dump
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

