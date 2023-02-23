---
id: ida
title: ida
hide_title: true
hide_table_of_contents: true
sidebar_label: ida
description: Analyze DSC in IDA Pro
---
## ipsw dyld ida

Analyze DSC in IDA Pro

```
ipsw dyld ida <DSC> <DYLIB> [DYLIBS...] [flags]
```

### Options

```
  -c, --delete-db         Disassemble a new file (delete the old database)
  -d, --dependancies      Analyze module dependencies
  -g, --enable-gui        Compress output folder
  -h, --help              help for ida
  -p, --ida-path string   IDA Pro directory (darwin default: /Applications/IDA Pro */ida64.app/Contents/MacOS)
  -l, --log-file string   IDA log file (default "ida.log")
  -o, --output string     Output folder (default "/Users/blacktop/Developer/Github/blacktop/ipsw")
      --slide string      dyld_shared_cache image ASLR slide value (hexadecimal)
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

