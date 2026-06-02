---
id: symbols
title: symbols
hide_title: true
hide_table_of_contents: true
sidebar_label: symbols
description: Emit IPSW symbols as JSONL
---
## ipsw symbols

Emit IPSW symbols as JSONL

### Synopsis

Emit every symbol in an IPSW as newline-delimited JSON (JSONL).

The stream is emitted in this order: one "ipsw" line, then for each image an
"image" line immediately followed by that image's "symbol" lines. Each
dyld_shared_cache also emits a one-time "dsc" line carrying shared_region_start,
which its dylib images reference via dsc_uuid.

Kernel and KEXT symbol addresses are bit-63-cleared exactly as the ipswd symbol
database stores them, so a server backed by this output returns byte-identical
results to the daemon.

```
ipsw symbols <IPSW> [flags]
```

### Options

```
      --dyld                Include dyld_shared_cache dylib symbols
      --filesystem          Include file system Mach-O symbols
  -h, --help                help for symbols
      --json                Emit symbols as JSONL (one JSON object per line)
      --kernel              Include kernelcache/KEXT symbols
  -o, --output string       Output file path ("-" or unset for stdout)
      --pem-db string       AEA pem DB JSON file
      --signatures string   Path to kernel symbolication signatures directory
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

