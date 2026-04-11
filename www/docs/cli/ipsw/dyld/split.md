---
id: split
title: split
hide_title: true
hide_table_of_contents: true
sidebar_label: split
description: Split DSC into dylibs using Xcode's dsc_extractor (macOS only)
---
## ipsw dyld split

Split DSC into dylibs using Xcode's dsc_extractor (macOS only)

### Synopsis

Split a dyld_shared_cache into individual dylibs using Apple's dsc_extractor.bundle.

This is a fast bulk operation but the output is not enriched for reverse engineering.
For RE use, prefer 'ipsw dyld extract' which adds local symbols, ObjC metadata,
and stub island symbols, works cross-platform, and produces IDA/Ghidra-ready MachOs.

```
ipsw dyld split <DSC> [flags]
```

### Options

```
  -b, --build string     Cache build
  -c, --cache            Build Xcode device support cache
  -h, --help             help for split
  -o, --output string    Directory to extract the dylibs (default: CWD)
  -v, --version string   Cache version
  -x, --xcode string     Path to Xcode.app
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

