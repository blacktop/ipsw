---
id: swift-dump
title: swift-dump
hide_title: true
hide_table_of_contents: true
sidebar_label: swift-dump
description: 🚧 Swift class-dump a dylib from a DSC or MachO
---
## ipsw swift-dump

🚧 Swift class-dump a dylib from a DSC or MachO

```
ipsw swift-dump [<DSC> <DYLIB>|<MACHO>] [flags]
```

### Options

```
      --all             Dump all other Swift sections/info
      --arch string     Which architecture to use for fat/universal MachO
  -a, --ass string      Dump associated type (regex)
      --demangle        Demangle symbol names
      --deps            Dump imported private frameworks
  -e, --ext string      Dump extension (regex)
  -h, --help            help for swift-dump
  -i, --interface       🚧 Dump Swift Interface
  -o, --output string   🚧 Folder to write interface to
  -p, --proto string    Dump protocol (regex)
      --theme string    Color theme (nord, github, etc) (default "nord")
  -y, --type string     Dump type (regex)
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

