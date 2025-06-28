---
id: info
title: info
hide_title: true
hide_table_of_contents: true
sidebar_label: info
description: Display IM4M manifest information
---
## ipsw img4 im4m info

Display IM4M manifest information

```
ipsw img4 im4m info <IM4M> [flags]
```

### Examples

```bash
# Display IM4M manifest information
❯ ipsw img4 im4m info manifest.im4m

# Output as JSON
❯ ipsw img4 im4m info --json manifest.im4m
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

* [ipsw img4 im4m](/docs/cli/ipsw/img4/im4m)	 - IM4M manifest operations

