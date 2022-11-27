---
id: info
title: info
hide_title: true
hide_table_of_contents: true
sidebar_label: info
description: Explore a MachO file
last_update:
  date: 2022-11-26T17:29:41-07:00
  author: blacktop
---
## ipsw macho info

Explore a MachO file

```
ipsw macho info <macho> [flags]
```

### Options

```
  -z, --all-fileset-entries     Parse all fileset entries
  -a, --arch string             Which architecture to use for fat/universal MachO
      --dump-cert               Dump the certificate
  -e, --ent                     Print entitlements
  -x, --extract-fileset-entry   Extract the fileset entry
  -t, --fileset-entry string    Which fileset entry to analyze
  -u, --fixups                  Print fixup chains
  -d, --header                  Print the mach header
  -h, --help                    help for info
  -l, --loads                   Print the load commands
  -o, --objc                    Print ObjC info
  -r, --objc-refs               Print ObjC references
      --output string           Directory to extract files to
  -s, --sig                     Print code signature
  -f, --starts                  Print function starts
  -c, --strings                 Print cstrings
  -n, --symbols                 Print symbols
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw macho](/docs/cli/ipsw/macho)	 - Parse MachO

