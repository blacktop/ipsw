---
id: mach-lookup
title: mach-lookup
hide_title: true
hide_table_of_contents: true
sidebar_label: mach-lookup
description: Find profiles that can look up a mach service
---
## ipsw sb query mach-lookup

Find profiles that can look up a mach service

```
ipsw sb query mach-lookup <TARGET> [KERNELCACHE] [flags]
```

### Options

```
  -h, --help   help for mach-lookup
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

