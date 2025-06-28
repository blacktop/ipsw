---
id: create
title: create
hide_title: true
hide_table_of_contents: true
sidebar_label: create
description: Create IM4R restore info with boot nonce
---
## ipsw img4 im4r create

Create IM4R restore info with boot nonce

```
ipsw img4 im4r create [flags]
```

### Examples

```bash
# Create IM4R with boot nonce for iOS restore
❯ ipsw img4 im4r create --boot-nonce 1234567890abcdef --output restore.im4r
```

### Options

```
  -n, --boot-nonce string   Boot nonce to set (8-byte hex string)
  -h, --help                help for create
  -o, --output string       Output IM4R file path
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw img4 im4r](/docs/cli/ipsw/img4/im4r)	 - IM4R restore info operations

