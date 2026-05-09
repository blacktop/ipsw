---
id: dec
title: dec
hide_title: true
hide_table_of_contents: true
sidebar_label: dec
description: Decompile sandbox profiles to compileable SBPL
---
## ipsw sb dec

Decompile sandbox profiles to compileable SBPL

### Synopsis

Decompile binary sandbox profiles from a kernelcache into human-readable,
compileable SBPL (Sandbox Profile Language), flat SBASM assembly, or structured JSON.

When no PROFILE name is given, all profiles in the collection are decompiled.

Examples:
  # Decompile all profiles
  ipsw sb dec kernelcache.release.iPhone18,1

  # Decompile a single profile
  ipsw sb dec kernelcache.release.iPhone18,1 com.apple.WebKit.WebContent

  # Output as flat assembly
  ipsw sb dec kernelcache.release.iPhone18,1 --format sbasm

  # Output as structured JSON (array of profile objects with SBPL)
  ipsw sb dec kernelcache.release.iPhone18,1 --format json

  # Write compileable SBPL to a file
  ipsw sb dec kernelcache.release.iPhone18,1 com.apple.WebKit.WebContent -O WebContent.sb

  # Decompile a pre-extracted profile blob
  ipsw sb dec --type profile -i sandbox_profile.bin -o operations.txt --darwin-version 25.0.0

  # Disable node budget for heavy profiles (may be slow)
  ipsw sb dec kernelcache.release.iPhone18,1 com.apple.CommCenter --full-graph

```
ipsw sb dec [KERNELCACHE] [PROFILE] [flags]
```

### Options

```
      --darwin-version string   Darwin version (required when operations list is provided without kernelcache)
  -f, --format string           Output format: sbpl, sbasm, or json (default "sbpl")
      --full-graph              Disable normalized-output node limit (may be slow)
  -h, --help                    help for dec
      --inline                  Inline parent-profile chain into a single SBPL document (SBPL only; requires PROFILE)
  -i, --input string            Input sandbox profile binary file
  -o, --operations string       Input operations list file (one operation per line)
  -O, --output string           Output path for plain compileable SBPL
      --type string             Sandbox source type: collection, protobox, or profile (default "collection")
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

