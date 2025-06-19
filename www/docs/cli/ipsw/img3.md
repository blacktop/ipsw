---
id: img3
title: img3
hide_title: true
hide_table_of_contents: true
sidebar_label: img3
description: Parse and optionally decrypt img3 files
---
## ipsw img3

Parse and optionally decrypt img3 files

```
ipsw img3 [flags]
```

### Options

```
  -h, --help            help for img3
      --iv string       IV for decryption (hex string)
  -k, --iv-key string   IV+Key for direct decryption (concatenated hex string)
      --key string      Key for decryption (hex string)
  -o, --output string   Output file for decrypted data
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

