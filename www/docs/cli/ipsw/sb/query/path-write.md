---
id: path-write
title: path-write
hide_title: true
hide_table_of_contents: true
sidebar_label: path-write
description: Find profiles that can write to a path
---
## ipsw sb query path-write

Find profiles that can write to a path

```
ipsw sb query path-write <TARGET> [KERNELCACHE] [flags]
```

### Options

```
  -h, --help   help for path-write
```

### Options inherited from parent commands

```
      --color                   colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --darwin-version string   Darwin version when using --operations without a kernelcache
      --graph string            Use a previously exported graph file instead of building from live sandbox inputs
  -i, --input string            Input sandbox profile binary file
      --no-color                disable colorize output
  -o, --operations string       Input operations list file (one operation per line)
  -O, --output string           Output format: table or json (default "table")
      --profile                 Build graph from a compiled sandbox profile instead of the builtin collection
  -V, --verbose                 verbose output
```

### SEE ALSO

* [ipsw sb query](/docs/cli/ipsw/sb/query)	 - Sandbox query commands

