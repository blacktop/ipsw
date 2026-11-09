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
  -h, --help[=true|false]   help for path-write
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --darwin-version string   Darwin version when using --operations without a kernelcache
      --graph string            Use a previously exported graph file instead of building from live sandbox inputs
  -i, --input string            Input sandbox profile binary file
      --no-color[=true|false]   disable colorize output
  -o, --operations string       Input operations list file (one operation per line)
  -O, --output string           Output format: pretty, table, or json (default "pretty")
      --profile[=true|false]    Build graph from a compiled sandbox profile instead of the builtin collection
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw sb query](/docs/cli/ipsw/sb/query)	 - Sandbox query commands

