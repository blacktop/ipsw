---
id: ls
title: ls
hide_title: true
hide_table_of_contents: true
sidebar_label: ls
description: List OTA files
---
## ipsw ota ls

List OTA files

### Synopsis

List OTA files. With --payload --json, output is a stream of JSON arrays, one per nonempty payload result. No matches produce no output.

```
ipsw ota ls <OTA> [flags]
```

### Options

```
  -b, --bom[=true|false]       List the post.bom files
  -h, --help[=true|false]      help for ls
  -j, --json[=true|false]      Output a JSON array per matching payload (requires --payload)
  -r, --pattern string         Regex pattern to match payloadv2 files (requires --payload)
  -p, --payload[=true|false]   List the payloadv2 files
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

