---
id: info
title: info
hide_title: true
hide_table_of_contents: true
sidebar_label: info
description: Display IPSW/OTA Info
---
## ipsw info

Display IPSW/OTA Info

```
ipsw info <IPSW> [flags]
```

### Options

```
  -h, --help[=true|false]       help for info
      --insecure[=true|false]   do not verify ssl certs
  -j, --json[=true|false]       Output as JSON
  -l, --list[=true|false]       List files in IPSW/OTA
  -k, --lookup[=true|false]     Lookup DMG keys on theapplewiki.com
      --proxy string            HTTP/HTTPS proxy
  -r, --remote[=true|false]     Extract from URL
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

