---
id: symbolicate
title: symbolicate
hide_title: true
hide_table_of_contents: true
sidebar_label: symbolicate
description: Symbolicate ARM 64-bit crash logs (similar to Apple's symbolicatecrash)
last_update:
  date: 2022-12-23T02:36:33-07:00
  author: blacktop
---
## ipsw symbolicate

Symbolicate ARM 64-bit crash logs (similar to Apple's symbolicatecrash)

```
ipsw symbolicate <crashlog> <dyld_shared_cache> [flags]
```

### Options

```
  -d, --demangle   Demangle symbol names
  -h, --help       help for symbolicate
  -u, --unslide    Unslide the crashlog for easier static analysis
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

