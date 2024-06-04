---
id: symbolicate
title: symbolicate
hide_title: true
hide_table_of_contents: true
sidebar_label: symbolicate
description: Symbolicate ARM 64-bit crash logs (similar to Apple's symbolicatecrash)
---
## ipsw symbolicate

Symbolicate ARM 64-bit crash logs (similar to Apple's symbolicatecrash)

```
ipsw symbolicate <CRASHLOG> [IPSW|DSC] [flags]
```

### Examples

```bash
# Symbolicate a panic crashlog (BugType=210) with an IPSW
  ❯ ipsw symbolicate panic-full-2024-03-21-004704.000.ips iPad_Pro_HFR_17.4_21E219_Restore.ipsw
# Pretty print a crashlog (BugType=309) these are usually symbolicated by the OS
  ❯ ipsw symbolicate --color Delta-2024-04-20-135807.ips
# Symbolicate a (old stype) crashlog (BugType=109) requiring a dyld_shared_cache to symbolicate
  ❯ ipsw symbolicate Delta-2024-04-20-135807.ips
    ⨯ please supply a dyld_shared_cache for iPhone13,3 running 14.5 (18E5154f)
```

### Options

```
  -a, --all        Show all threads in crashlog
  -d, --demangle   Demangle symbol names
  -h, --help       help for symbolicate
  -r, --running    Show all running (TH_RUN) threads in crashlog
  -u, --unslide    Unslide the crashlog for easier static analysis
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

