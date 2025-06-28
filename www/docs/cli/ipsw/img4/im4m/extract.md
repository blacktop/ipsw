---
id: extract
title: extract
hide_title: true
hide_table_of_contents: true
sidebar_label: extract
description: Extract IM4M manifest from SHSH blob
---
## ipsw img4 im4m extract

Extract IM4M manifest from SHSH blob

```
ipsw img4 im4m extract <IM4M> [flags]
```

### Examples

```bash
# Extract IM4M from SHSH blob
❯ ipsw img4 im4m extract shsh.blob

# Extract update manifest (if available)
❯ ipsw img4 im4m extract --update shsh.blob

# Extract no-nonce manifest (if available)
❯ ipsw img4 im4m extract --no-nonce shsh.blob

# Extract to specific output file
❯ ipsw img4 im4m extract --output custom.im4m shsh.blob
```

### Options

```
  -h, --help            help for extract
  -n, --no-nonce        Extract no-nonce Image4 manifest (if available)
  -o, --output string   Output file path
  -u, --update          Extract update Image4 manifest (if available)
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw img4 im4m](/docs/cli/ipsw/img4/im4m)	 - IM4M manifest operations

