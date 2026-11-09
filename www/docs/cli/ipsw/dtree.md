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
ipsw dtree <IPSW/OTA/DeviceTree> [flags]
```

### Options

```
  -y, --confirm[=true|false]    Skip confirmation prompt for OTA downloads
  -f, --filter string           Filter DeviceTree to parse (if multiple i.e. macOS)
  -h, --help[=true|false]       help for dtree
      --insecure[=true|false]   do not verify ssl certs
  -j, --json[=true|false]       Output to stdout as JSON
      --key-db string           Path to AEA keys JSON database (auto-lookup by filename)
      --key-val string          Base64 encoded AEA symmetric encryption key
      --proxy string            HTTP/HTTPS proxy
  -r, --remote[=true|false]     Extract from URL
  -s, --summary[=true|false]    Output summary only
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

