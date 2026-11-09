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

### Synopsis

Disassemble an ARM64 MachO file or the main executable in an IPA archive.

Image-wide symbols are cached in `<input>.a2s`. Use --cache to choose another path,
or --quiet to skip symbol analysis.

```
ipsw macho disass <MACHO|IPA> [flags]
```

### Options

```
  -z, --all-fileset-entries[=true|false]   Parse all fileset entries
      --arch string                        Which architecture to use for fat/universal MachO
      --cache string                       Path to .a2s addr to sym cache file (speeds up analysis)
  -c, --count uint                         Number of instructions to disassemble
  -D, --dec[=true|false]                   Decompile assembly
      --dec-api-key-env string             Environment variable holding the OpenAI-compatible API key (defaults to OPENAI_API_KEY)
      --dec-base-url string                OpenAI-compatible API base URL (defaults to OPENAI_BASE_URL)
      --dec-lang string                    Language to decompile to (C, ObjC or Swift)
      --dec-llm string                     LLM provider to use for decompilation
      --dec-model string                   LLM model to use for decompilation
      --dec-nocache[=true|false]           Do not use decompilation cache
      --dec-retries int                    Number of retries for LLM decompilation
      --dec-retry-backoff duration         Backoff time between retries (e.g. '30s', '2m') (default 30s)
      --dec-temp float                     LLM temperature for decompilation (default 0.2)
      --dec-theme string                   Decompilation color theme (nord, github, etc) (default "nord")
      --dec-top-p float                    LLM top_p for decompilation (default 0.1)
  -d, --demangle[=true|false]              Demangle symbol names
  -e, --entry[=true|false]                 Disassemble entry point
  -t, --fileset-entry string               Which fileset entry to analyze
      --force[=true|false]                 Continue to disassemble even if there are analysis errors
  -h, --help[=true|false]                  help for disass
  -j, --json[=true|false]                  Output as JSON
  -o, --off uint                           File offset to start disassembling
  -q, --quiet[=true|false]                 Do NOT markup analysis (Faster)
  -x, --section string                     Disassemble an entire segment/section (i.e. __TEXT_EXEC.__text)
  -s, --symbol string                      Function to disassemble
  -a, --vaddr uint                         Virtual address to start disassembling
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw macho](/docs/cli/ipsw/macho)	 - Parse MachO

