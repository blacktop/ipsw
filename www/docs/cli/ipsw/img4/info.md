---
id: info
title: info
hide_title: true
hide_table_of_contents: true
sidebar_label: info
description: Display IMG4 file information
---
## ipsw img4 info

Display IMG4 file information

```
ipsw img4 info <IMG4> [flags]
```

### Examples

```bash
# Display information about an IMG4 file
❯ ipsw img4 info kernel.img4

# Output information as JSON
❯ ipsw img4 info --json kernel.img4
```

### Options

```
  -h, --help   help for info
  -j, --json   Output as JSON
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw img4](/docs/cli/ipsw/img4)	 - Parse and manipulate IMG4 files

