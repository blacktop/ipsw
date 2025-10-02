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

```
ipsw ota payload <PAYLOAD>|<OTA> <PAYLOAD> [flags]
```

### Options

```
  -d, --dirs    Directories only
  -f, --files   Files only
  -h, --help    help for payload
```

### Options inherited from parent commands

```
      --color            colorize output
      --config string    config file (default is $HOME/.config/ipsw/config.yaml)
      --insecure         Allow insecure connections when fetching AEA keys
      --key-db string    Path to AEA keys JSON database (auto-lookup by filename)
      --key-val string   Base64 encoded AEA symmetric encryption key
      --no-color         disable colorize output
  -V, --verbose          verbose output
```

### SEE ALSO

* [ipsw ota](/docs/cli/ipsw/ota)	 - Parse OTAs

