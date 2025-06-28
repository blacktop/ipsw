---
id: create
title: create
hide_title: true
hide_table_of_contents: true
sidebar_label: create
description: Create IM4P payload from raw data
---
## ipsw img4 im4p create

Create IM4P payload from raw data

```
ipsw img4 im4p create <input-file> [flags]
```

### Options

```
  -c, --compress string   Compress payload (lzfse, lzss, none) (default "none")
  -e, --extra string      Extra data file to append
  -h, --help              help for create
  -o, --output string     Output file path
  -t, --type string       Type string (required)
  -v, --version string    Version string
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

