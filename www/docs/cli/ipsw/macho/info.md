---
id: info
title: info
hide_title: true
hide_table_of_contents: true
sidebar_label: info
description: Explore a MachO file
---
## ipsw macho info

Explore a MachO file

### Synopsis

Explore a MachO file, app bundle, or the main executable in an IPA archive.

```
ipsw macho info <macho|app|ipa> [flags]
```

### Options

```
  -z, --all-fileset-entries[=true|false]     Parse all fileset entries
  -a, --arch string                          Which architecture to use for fat/universal MachO
  -b, --bit-code[=true|false]                Dump the LLVM bitcode
      --demangle[=true|false]                Demangle symbol names
      --dump-cert[=true|false]               Dump the certificate
  -e, --ent[=true|false]                     Print entitlements
      --ent-der[=true|false]                 Print DER entitlements
  -x, --extract-fileset-entry[=true|false]   Extract the fileset entry
  -t, --fileset-entry string                 Which fileset entry to analyze
  -u, --fixups[=true|false]                  Print fixup chains
  -d, --header[=true|false]                  Print the mach header
  -h, --help[=true|false]                    help for info
  -j, --json[=true|false]                    Print the TOC as JSON
  -l, --loads[=true|false]                   Print the load commands
  -o, --objc[=true|false]                    Print ObjC info
      --objc-refs[=true|false]               Print ObjC references
      --output string                        Directory to extract files to
  -s, --sig[=true|false]                     Print code signature
  -g, --split-seg[=true|false]               Print split seg info
  -f, --starts[=true|false]                  Print function starts
  -c, --strings[=true|false]                 Print cstrings
  -w, --swift[=true|false]                   Print Swift info
      --swift-all[=true|false]               Print all other Swift sections info
  -n, --symbols[=true|false]                 Print symbols
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

