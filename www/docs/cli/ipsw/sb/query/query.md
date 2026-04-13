---
id: query
title: query
hide_title: true
hide_table_of_contents: true
sidebar_label: query
description: Sandbox query commands
---
## ipsw sb query

Sandbox query commands

```
ipsw sb query [flags]
```

### Examples

```bash
# Two input modes — pick one, not both:
#   --graph FILE     load a pre-exported graph (fast, no kernelcache arg)
#   [KERNELCACHE]    build the graph fresh (~40s per query)

# RECOMMENDED: export once, query many times
❯ ipsw sb graph export kernelcache.release.iPhone18,1 -O graph.json

# Which profiles can open an IOKit user client class?
❯ ipsw sb query iokit-open IOSurfaceRootUserClient --graph graph.json

# Which profiles can read a path?
❯ ipsw sb query path-read /private/var/mobile/Library/Preferences --graph graph.json

# Which profiles can write to a path?
❯ ipsw sb query path-write /private/var/mobile/tmp --graph graph.json

# Which profiles can call a syscall? (number, SYS_ name, or alias)
❯ ipsw sb query syscall mmap --graph graph.json
❯ ipsw sb query syscall 197 --graph graph.json

# Which profiles can look up a mach service?
❯ ipsw sb query mach-lookup com.apple.mobilegestalt.xpc --graph graph.json

# Which profiles can register a mach service? (global-name or local-name)
❯ ipsw sb query mach-register com.apple.assertiond.processassertionconnection --graph graph.json

# Which profiles can read/write a sysctl?
❯ ipsw sb query sysctl kern.osversion --graph graph.json

# Which profiles can read/write a preference domain?
❯ ipsw sb query preference com.apple.UIKit --graph graph.json

# Which profiles can post a notification?
❯ ipsw sb query notification com.apple.mobile.keybagd.lock_status --graph graph.json

# JSON output for scripting
❯ ipsw sb query iokit-open IOSurfaceRootUserClient --graph graph.json -O json \
    | jq -r '.matches[] | select(.decision=="allow") | .profile' | sort -u

# Show guard conditions per profile
❯ ipsw sb query path-write /var/mobile/foo --graph graph.json -O json \
    | jq -r '.matches[] | "\(.profile): \(.guard_string)"'

# Or skip export and build fresh from kernelcache (no --graph; ~40s each query)
❯ ipsw sb query sysctl kern.osversion kernelcache.release.iPhone18,1
```

### Options

```
      --darwin-version string   Darwin version when using --operations without a kernelcache
      --graph string            Use a previously exported graph file instead of building from live sandbox inputs
  -h, --help                    help for query
  -i, --input string            Input sandbox profile binary file
  -o, --operations string       Input operations list file (one operation per line)
  -O, --output string           Output format: table or json (default "table")
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

* [ipsw sb](/docs/cli/ipsw/sb)	 - Sandbox commands
* [ipsw sb query cypher](/docs/cli/ipsw/sb/query/cypher)	 - Run a constrained sandbox graph query
* [ipsw sb query iokit-open](/docs/cli/ipsw/sb/query/iokit-open)	 - Find profiles that can open an IOKit user client class
* [ipsw sb query mach-lookup](/docs/cli/ipsw/sb/query/mach-lookup)	 - Find profiles that can look up a mach service
* [ipsw sb query mach-register](/docs/cli/ipsw/sb/query/mach-register)	 - Find profiles that can register a mach service
* [ipsw sb query notification](/docs/cli/ipsw/sb/query/notification)	 - Find profiles that can post a darwin/distributed notification
* [ipsw sb query path-read](/docs/cli/ipsw/sb/query/path-read)	 - Find profiles that can read from a path
* [ipsw sb query path-write](/docs/cli/ipsw/sb/query/path-write)	 - Find profiles that can write to a path
* [ipsw sb query preference](/docs/cli/ipsw/sb/query/preference)	 - Find profiles that can read/write a preference domain
* [ipsw sb query syscall](/docs/cli/ipsw/sb/query/syscall)	 - Find profiles that can call a syscall
* [ipsw sb query sysctl](/docs/cli/ipsw/sb/query/sysctl)	 - Find profiles that can read/write a sysctl

