---
id: info
title: info
hide_title: true
hide_table_of_contents: true
sidebar_label: info
description: Display detailed IM4P information
---
## ipsw img4 im4p info

Display detailed IM4P information

```
ipsw img4 im4p info <IM4P> [flags]
```

### Examples

```bash
# Display IM4P information
❯ ipsw img4 im4p info kernelcache.im4p

# Output as JSON
❯ ipsw img4 im4p info --json kernelcache.im4p
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

* [ipsw img4 im4p](/docs/cli/ipsw/img4/im4p)	 - IM4P payload operations

