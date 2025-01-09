---
id: disass
title: disass
hide_title: true
hide_table_of_contents: true
sidebar_label: disass
description: Disassemble at symbol/vaddr
---
## ipsw dyld disass

Disassemble at symbol/vaddr

```
ipsw dyld disass <DSC> [flags]
```

### Examples

```bash
# Disassemble all images in dyld_shared_cache
❯ ipsw dsc disass DSC
# Disassemble a few dylibs in dyld_shared_cache (NOTE: multiple -i flags OR comma separated dylibs)
❯ ipsw dsc disass DSC --image libsystem_kernel.dylib --image libsystem_platform.dylib,libsystem_pthread.dylib
# Disassemble a symbol in dyld_shared_cache (NOTE: supply --symbol-image 'libsystem_malloc.dylib' for faster lookup)
❯ ipsw dsc disass DSC --symbol _malloc
# Disassemble a function at a virtual address in dyld_shared_cache
❯ ipsw dsc disass DSC --vaddr 0x1b19d6940
# Disassemble a function at a virtual address in dyld_shared_cache and output as JSON
❯ ipsw dsc disass DSC --vaddr 0x1b19d6940 --json
# Disassemble a function at a virtual address in dyld_shared_cache and demangle symbol names
❯ ipsw dsc disass DSC --vaddr 0x1b19d6940 --demangle
# Disassemble a function at a virtual address in dyld_shared_cache and do NOT markup analysis (Faster)
❯ ipsw dsc disass DSC --vaddr 0x1b19d6940 --quiet
```

### Options

```
      --cache string          Path to .a2s addr to sym cache file (speeds up analysis)
  -c, --count uint            Number of instructions to disassemble
  -d, --demangle              Demangle symbol names
      --force                 Continue to disassemble even if there are analysis errors
  -h, --help                  help for disass
  -i, --image strings         Dylib(s) to disassemble
      --input string          Input function JSON file
  -j, --json                  Output as JSON
  -q, --quiet                 Do NOT markup analysis (Faster)
  -s, --symbol string         Function to disassemble
      --symbol-image string   Dylib to search for symbol (speeds up symbol lookup)
  -a, --vaddr uint            Virtual address to start disassembling
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

