---
id: pkg
title: pkg
hide_title: true
hide_table_of_contents: true
sidebar_label: pkg
description: 🚧 List contents of a DMG/PKG file
---
## ipsw pkg

🚧 List contents of a DMG/PKG file

```
ipsw pkg PKG [flags]
```

### Options

```
  -a, --all[=true|false]       Show all contents
  -b, --bom[=true|false]       Show BOM
  -d, --dist[=true|false]      Show distribution
  -f, --flat[=true|false]      Do NOT preserve directory structure when extracting with --pattern
  -h, --help[=true|false]      help for pkg
  -o, --output string          Output folder
  -p, --pattern string         Extract files that match regex
  -l, --pay[=true|false]       Show Payload
  -s, --scripts[=true|false]   Show scripts
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

