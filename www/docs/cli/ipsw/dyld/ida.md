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
  -a, --all[=true|false]            Analyze whole cache (this will take a while)
  -c, --delete-db[=true|false]      Disassemble a new file (delete the old database)
  -d, --dependancies[=true|false]   Analyze module dependencies
      --diaphora-db string          Path to Diaphora database
  -k, --docker[=true|false]         Run IDA Pro in a docker container
      --docker-entry string         IDA Pro docker entrypoint (default "/ida/idat64")
      --docker-image string         IDA Pro docker image (default "blacktop/idapro:8.2-pro")
  -g, --enable-gui[=true|false]     Enable IDA Pro GUI (defaults to headless)
  -e, --extra-args strings          IDA Pro CLI extra arguments
  -h, --help[=true|false]           help for ida
  -p, --ida-path string             IDA Pro directory (darwin default: /Applications/IDA Pro */ida64.app/Contents/MacOS)
  -l, --log-file string             IDA log file
  -o, --output string               Output folder
  -s, --script string               IDA Pro script to run
  -r, --script-args strings         IDA Pro script arguments
      --slide string                dyld_shared_cache image ASLR slide value (hexadecimal)
  -t, --temp-db[=true|false]        Do not create a database file (requires --enable-gui)
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

