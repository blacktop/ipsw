---
id: ent
title: ent
hide_title: true
hide_table_of_contents: true
sidebar_label: ent
description: Manage and search entitlements database
---
## ipsw ent

Manage and search entitlements database

```
ipsw ent [flags]
```

### Examples

```bash
# Create SQLite database from IPSW
❯ ipsw ent --sqlite entitlements.db --ipsw iPhone16,1_18.2_22C150_Restore.ipsw

# Create database from multiple IPSWs
❯ ipsw ent --sqlite entitlements.db --ipsw *.ipsw

# Create PostgreSQL database from IPSW (for Supabase)
❯ ipsw ent --pg-host db.xyz.supabase.co --pg-user postgres --pg-password your-password --pg-database postgres --ipsw iPhone16,1_18.2_22C150_Restore.ipsw

# Search for entitlement key
❯ ipsw ent --sqlite entitlements.db --key platform-application

# Search for entitlement value
❯ ipsw ent --sqlite entitlements.db --value LockdownMode

# Search for specific file
❯ ipsw ent --sqlite entitlements.db --file WebContent

# Filter by iOS version and search
❯ ipsw ent --sqlite entitlements.db --version 18.2 --key sandbox

# Show database statistics
❯ ipsw ent --sqlite entitlements.db --stats

# Search PostgreSQL database (Supabase)
❯ ipsw ent --pg-host db.xyz.supabase.co --pg-user postgres --pg-password your-password --pg-database postgres --key sandbox
```

### Options

```
  -f, --file string          Search for file path pattern
      --file-only            Only output file paths
  -h, --help                 help for ent
      --input stringArray    Folders of MachOs to analyze
      --ipsw stringArray     IPSWs to process
  -k, --key string           Search for entitlement key pattern
      --limit int            Limit number of results (default 100)
      --pg-database string   PostgreSQL database name
      --pg-host string       PostgreSQL host
      --pg-password string   PostgreSQL password
      --pg-port string       PostgreSQL port (default "5432")
      --pg-sslmode string    PostgreSQL SSL mode (disable, require, verify-ca, verify-full) (default "require")
      --pg-user string       PostgreSQL user
      --sqlite string        Path to SQLite database
      --stats                Show database statistics
  -v, --value string         Search for entitlement value pattern
      --version string       Filter by iOS version
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

