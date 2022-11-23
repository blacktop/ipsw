---
id: ipsw_macho_disass
title: ipsw macho disass
hide_title: true
sidebar_label: disass
description: Disassemble ARM64 MachO at symbol/vaddr
last_update:
  date: 2022-11-23T16:33:46-07:00
  author: blacktop
---
# ipsw macho disass

Disassemble ARM64 MachO at symbol/vaddr

```
ipsw macho disass <MACHO> [flags]
```

## Options

```
  -z, --all-fileset-entries    Parse all fileset entries
      --cache string           Path to .a2s addr to sym cache file (speeds up analysis)
  -c, --count uint             Number of instructions to disassemble
  -d, --demangle               Demangle symbol names
  -t, --fileset-entry string   Which fileset entry to analyze
  -h, --help                   help for disass
  -j, --json                   Output as JSON
  -q, --quiet                  Do NOT markup analysis (Faster)
  -x, --section string         Disassemble an entire segment/section (i.e. __TEXT_EXEC.__text)
  -s, --symbol string          Function to disassemble
  -a, --vaddr uint             Virtual address to start disassembling
```

## Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

## See also

* [ipsw macho](/docs/cli/macho/ipsw_macho)	 - Parse MachO

