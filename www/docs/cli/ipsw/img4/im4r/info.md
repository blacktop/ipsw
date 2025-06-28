---
id: info
title: info
hide_title: true
hide_table_of_contents: true
sidebar_label: info
description: Display IM4R restore information
---
## ipsw img4 im4r info

Display IM4R restore information

```
ipsw img4 im4r info <IMG4> [flags]
```

### Examples

```bash
# Display IM4R restore info from IMG4 file
❯ ipsw img4 im4r info kernel.img4

# Output as JSON
❯ ipsw img4 im4r info --json kernel.img4
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

* [ipsw img4 im4r](/docs/cli/ipsw/img4/im4r)	 - IM4R restore info operations

