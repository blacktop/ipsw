---
id: payload
title: payload
hide_title: true
hide_table_of_contents: true
sidebar_label: payload
description: List contents of a payloadv2 file
---
## ipsw ota payload

List contents of a payloadv2 file

### Synopsis

List contents of a raw, PBZX, or PBZM payloadv2 file. PBZM requires Apple's aa tool with PBZM support.

```
ipsw ota payload <PAYLOAD> | <OTA> <PAYLOAD> [flags]
```

### Options

```
  -d, --dirs[=true|false]    Directories only
  -f, --files[=true|false]   Files only
  -h, --help[=true|false]    help for payload
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --insecure[=true|false]   Allow insecure connections when fetching AEA keys
      --key-db string           Path to AEA keys JSON database (auto-lookup by filename)
      --key-val string          Base64 encoded AEA symmetric encryption key
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw ota](/docs/cli/ipsw/ota)	 - Parse OTAs

