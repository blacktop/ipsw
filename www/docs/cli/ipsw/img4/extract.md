---
id: extract
title: extract
hide_title: true
hide_table_of_contents: true
sidebar_label: extract
description: Extract IMG4 components
---
## ipsw img4 extract

Extract IMG4 components

```
ipsw img4 extract <IMG4> [flags]
```

### Examples

```bash
# Extract IM4P payload from IMG4 file
❯ ipsw img4 extract --im4p kernel.img4

# Extract manifest and restore info
❯ ipsw img4 extract --im4m --im4r kernel.img4

# Extract all components to a specific directory
❯ ipsw img4 extract --im4p --im4m --im4r --output /tmp/extracted kernel.img4

# Extract raw (compressed) IM4P data without decompression
❯ ipsw img4 extract --im4p --raw kernel.img4
```

### Options

```
  -h, --help[=true|false]   help for extract
  -m, --im4m[=true|false]   Extract IM4M manifest to path
  -p, --im4p[=true|false]   Extract IM4P payload to path
  -r, --im4r[=true|false]   Extract IM4R restore info to path
  -o, --output string       Output folder
      --raw[=true|false]    Extract raw IM4P data without decompression
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw img4](/docs/cli/ipsw/img4)	 - Parse and manipulate IMG4 files

