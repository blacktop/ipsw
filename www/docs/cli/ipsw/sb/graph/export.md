---
id: export
title: export
hide_title: true
hide_table_of_contents: true
sidebar_label: export
description: Export sandbox graph
---
## ipsw sb graph export

Export sandbox graph

```
ipsw sb graph export [KERNELCACHE] [flags]
```

### Options

```
      --darwin-version string   Darwin version when using --operations without a kernelcache
  -f, --format string           Export format: json or protobuf (typed graph schema) (default "json")
  -h, --help[=true|false]       help for export
  -i, --input string            Input sandbox profile binary file
  -o, --operations string       Input operations list file (one operation per line)
  -O, --output string           Output path for exported graph
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

