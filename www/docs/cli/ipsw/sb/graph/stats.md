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
  -h, --help                    help for stats
  -i, --input string            Input sandbox profile binary file
  -o, --operations string       Input operations list file (one operation per line)
      --profile                 Build graph from a compiled sandbox profile instead of the builtin collection
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw sb graph](/docs/cli/ipsw/sb/graph)	 - Sandbox graph commands

