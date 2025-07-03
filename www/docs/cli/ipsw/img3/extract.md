---
id: extract
title: extract
hide_title: true
hide_table_of_contents: true
sidebar_label: extract
description: Extract data from img3 files
---
## ipsw img3 extract

Extract data from img3 files

```
ipsw img3 extract [flags]
```

### Options

```
  -h, --help            help for extract
      --iv string       IV for decryption (hex string)
  -k, --iv-key string   IV+Key for direct decryption (concatenated hex string)
      --key string      Key for decryption (hex string)
  -o, --output string   Output file for extracted data
  -r, --raw             Extract raw data (no decryption)
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw img3](/docs/cli/ipsw/img3)	 - Parse Img3

