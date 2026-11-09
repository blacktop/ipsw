---
id: cypher
title: cypher
hide_title: true
hide_table_of_contents: true
sidebar_label: cypher
description: Run a constrained sandbox graph query
---
## ipsw sb query cypher

Run a constrained sandbox graph query

### Synopsis

Run a constrained Cypher-like query over the local sandbox graph. Supported patterns are FILTERED_BY lookups, REQUIRES lookups, NOT EXISTS((o)-[:FILTERED_BY]->()) checks, and the documented profile-comparison pattern.

```
ipsw sb query cypher <QUERY> [KERNELCACHE] [flags]
```

### Options

```
  -h, --help[=true|false]   help for cypher
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

