---
id: disass
title: disass
hide_title: true
hide_table_of_contents: true
sidebar_label: disass
description: Disassemble dyld_shared_cache at symbol/vaddr
last_update:
  date: 2022-11-26T17:36:57-07:00
  author: blacktop
---
## ipsw dyld disass

Disassemble dyld_shared_cache at symbol/vaddr

```
ipsw dyld disass <dyld_shared_cache> [flags]
```

### Options

```
      --cache string    Path to .a2s addr to sym cache file (speeds up analysis)
  -c, --count uint      Number of instructions to disassemble
  -d, --demangle        Demangle symbol names
  -h, --help            help for disass
  -i, --image string    dylib image to search
      --input string    Input function JSON file
  -j, --json            Output as JSON
  -q, --quiet           Do NOT markup analysis (Faster)
  -s, --symbol string   Function to disassemble
  -a, --vaddr uint      Virtual address to start disassembling
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

