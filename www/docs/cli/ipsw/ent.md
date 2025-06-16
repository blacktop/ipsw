---
id: ent
title: ent
hide_title: true
hide_table_of_contents: true
sidebar_label: ent
description: Manage and search entitlements in SQLite database
---
## ipsw ent

Manage and search entitlements in SQLite database

```
ipsw ent [flags]
```

### Examples

```bash
# Create SQLite database from IPSW
❯ ipsw ent --db entitlements.db --ipsw iPhone16,1_18.2_22C150_Restore.ipsw

# Create database from multiple IPSWs  
❯ ipsw ent --db entitlements.db --ipsw *.ipsw

# Search for entitlement key
❯ ipsw ent --db entitlements.db --key platform-application

# Search for entitlement value
❯ ipsw ent --db entitlements.db --value LockdownMode

# Search for specific file
❯ ipsw ent --db entitlements.db --file WebContent

# Filter by iOS version and search
❯ ipsw ent --db entitlements.db --version 18.2 --key sandbox

# Show database statistics
❯ ipsw ent --db entitlements.db --stats

# GitHub Action usage (for automation)
❯ ipsw ent --db www/static/db/ipsw.db --ipsw latest.ipsw
```

### Options

```
      --db string           Path to SQLite database
  -f, --file string         Search for file path pattern
      --file-only           Only output file paths
  -h, --help                help for ent
      --input stringArray   Folders of MachOs to analyze
      --ipsw stringArray    IPSWs to process
  -k, --key string          Search for entitlement key pattern
      --limit int           Limit number of results (default 100)
      --stats               Show database statistics
  -v, --value string        Search for entitlement value pattern
      --version string      Filter by iOS version
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

