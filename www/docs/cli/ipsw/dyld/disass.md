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
# Decompile a function at a virtual address in dyld_shared_cache (via GitHub Copilot)
❯ ipsw dsc disass DSC --vaddr 0x1b19d6940 --dec --dec-model "Claude 3.7 Sonnet"
# Decompile a function using OpenRouter to access various models
❯ ipsw dsc disass DSC --vaddr 0x1b19d6940 --dec --dec-llm openrouter --dec-model "OpenAI: GPT-4o-mini"
```

### Options

```
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
      --dylibs                       Analyze all dylibs loaded by the image as well (could improve accuracy)
      --force                        Continue to disassemble even if there are analysis errors
  -h, --help                         help for disass
  -i, --image strings                Dylib(s) to disassemble
      --input string                 Input function JSON file
  -j, --json                         Output as JSON
  -q, --quiet                        Do NOT markup analysis (Faster)
  -s, --symbol string                Function to disassemble
      --symbol-image string          Dylib to search for symbol (speeds up symbol lookup)
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

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

