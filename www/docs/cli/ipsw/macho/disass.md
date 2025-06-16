---
id: disass
title: disass
hide_title: true
hide_table_of_contents: true
sidebar_label: disass
description: Disassemble ARM64 MachO at symbol/vaddr
---
## ipsw macho disass

Disassemble ARM64 MachO at symbol/vaddr

```
ipsw macho disass <MACHO> [flags]
```

### Options

```
  -z, --all-fileset-entries          Parse all fileset entries
      --arch string                  Which architecture to use for fat/universal MachO
      --cache string                 Path to .a2s addr to sym cache file (speeds up analysis)
  -c, --count uint                   Number of instructions to disassemble
  -D, --dec                          Decompile assembly
      --dec-lang string              Language to decompile to (C, ObjC or Swift)
      --dec-llm string               LLM provider to use for decompilation (ollama, copilot, etc.) (default "copilot")
      --dec-model string             LLM model to use for decompilation
      --dec-nocache                  Do not use decompilation cache
      --dec-retries int              Number of retries for LLM decompilation
      --dec-retry-backoff duration   Backoff time between retries (e.g. '30s', '2m') (default 30s)
      --dec-temp float               LLM temperature for decompilation (default 0.2)
      --dec-theme string             Decompilation color theme (nord, github, etc) (default "nord")
      --dec-top-p float              LLM top_p for decompilation (default 0.1)
  -d, --demangle                     Demangle symbol names
  -e, --entry                        Disassemble entry point
  -t, --fileset-entry string         Which fileset entry to analyze
      --force                        Continue to disassemble even if there are analysis errors
  -h, --help                         help for disass
  -j, --json                         Output as JSON
  -o, --off uint                     File offset to start disassembling
  -q, --quiet                        Do NOT markup analysis (Faster)
  -x, --section string               Disassemble an entire segment/section (i.e. __TEXT_EXEC.__text)
  -s, --symbol string                Function to disassemble
  -a, --vaddr uint                   Virtual address to start disassembling
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw macho](/docs/cli/ipsw/macho)	 - Parse MachO

