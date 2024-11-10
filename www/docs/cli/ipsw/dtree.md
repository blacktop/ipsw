---
id: dtree
title: dtree
hide_title: true
hide_table_of_contents: true
sidebar_label: dtree
description: Parse DeviceTree
---
## ipsw dtree

Parse DeviceTree

```
ipsw dtree <DeviceTree> [flags]
```

### Options

```
  -f, --filter string   Filter DeviceTree to parse (if multiple i.e. macOS)
  -h, --help            help for dtree
      --insecure        do not verify ssl certs
  -j, --json            Output to stdout as JSON
      --proxy string    HTTP/HTTPS proxy
  -r, --remote          Extract from URL
  -s, --summary         Output summary only
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

