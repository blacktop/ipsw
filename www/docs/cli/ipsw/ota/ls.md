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

```
ipsw ota ls <OTA> [flags]
```

### Options

```
  -b, --bom              List the post.bom files
  -h, --help             help for ls
  -j, --json             Output in JSON format
  -r, --pattern string   Regex pattern to match payloadv2 files
  -p, --payload          List the payloadv2 files
```

### Options inherited from parent commands

```
      --color            colorize output
      --config string    config file (default is $HOME/.config/ipsw/config.yaml)
      --key-val string   Base64 encoded symmetric encryption key
      --no-color         disable colorize output
  -V, --verbose          verbose output
```

### SEE ALSO

* [ipsw ota](/docs/cli/ipsw/ota)	 - Parse OTAs

