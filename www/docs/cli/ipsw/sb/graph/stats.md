---
id: stats
title: stats
hide_title: true
hide_table_of_contents: true
sidebar_label: stats
description: Show sandbox graph statistics
---
## ipsw sb graph stats

Show sandbox graph statistics

```
ipsw sb graph stats [KERNELCACHE] [flags]
```

### Options

```
      --darwin-version string   Darwin version when using --operations without a kernelcache
  -h, --help[=true|false]       help for stats
  -i, --input string            Input sandbox profile binary file
  -o, --operations string       Input operations list file (one operation per line)
      --profile[=true|false]    Build graph from a compiled sandbox profile instead of the builtin collection
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw sb graph](/docs/cli/ipsw/sb/graph)	 - Sandbox graph commands

