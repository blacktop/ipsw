---
id: class-dump
title: class-dump
hide_title: true
hide_table_of_contents: true
sidebar_label: class-dump
description: ObjC class-dump a dylib from a DSC or MachO
---
## ipsw class-dump

ObjC class-dump a dylib from a DSC or MachO

```
ipsw class-dump [<DSC> <DYLIB>|<MACHO>] [flags]
```

### Options

```
      --arch string     Which architecture to use for fat/universal MachO
  -a, --cat string      Dump category (regex)
  -c, --class string    Dump class (regex)
      --demangle        Demangle symbol names (same as verbose)
      --deps            Dump imported private frameworks
      --headers         Dump ObjC headers
  -h, --help            help for class-dump
  -o, --output string   Folder to write headers to
  -p, --proto string    Dump protocol (regex)
      --re              RE verbosity (with addresses)
      --refs            Dump ObjC references too
  -s, --spm             🚧 Generate a Swift Package for the dylib
      --theme string    Color theme (nord, github, etc) (default "nord")
  -x, --xcfw            🚧 Generate a XCFramework for the dylib
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

