---
id: dmg
title: dmg
hide_title: true
hide_table_of_contents: true
sidebar_label: dmg
description: 🚧 List/Extract DMG partiton/blocks
---
## ipsw disk dmg

🚧 List/Extract DMG partiton/blocks

```
ipsw disk dmg <DMG> [flags]
```

### Options

```
  -d, --decrypt[=true|false]   Decrypt DMG
  -h, --help[=true|false]      help for dmg
  -k, --key string             Encrypted DMG key
  -o, --output string          Output file
  -p, --partition int          Extract a specific partition by number (default -1)
  -w, --password string        Encrypted DMG password
  -r, --re string              Extract partition that matches regex
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw disk](/docs/cli/ipsw/disk)	 - Disk commands

