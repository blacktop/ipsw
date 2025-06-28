---
id: extract
title: extract
hide_title: true
hide_table_of_contents: true
sidebar_label: extract
description: Extract IM4P data
---
## ipsw img4 im4p extract

Extract IM4P data

### Synopsis

Extract IM4P payload data or extra metadata.

```
ipsw img4 im4p extract <IM4P> [flags]
```

### Options

```
  -e, --extra           Extract extra data
  -h, --help            help for extract
  -i, --iv string       AES iv for decryption
      --iv-key string   AES iv+key for decryption
  -b, --kbag            Extract keybags as JSON
  -k, --key string      AES key for decryption
  -o, --output string   Output file path
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw img4 im4p](/docs/cli/ipsw/img4/im4p)	 - IM4P payload operations

