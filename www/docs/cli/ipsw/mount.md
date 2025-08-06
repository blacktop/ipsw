---
id: mount
title: mount
hide_title: true
hide_table_of_contents: true
sidebar_label: mount
description: Mount DMG from IPSW
---
## ipsw mount

Mount DMG from IPSW

```
ipsw mount [fs|sys|app|exc] IPSW [flags]
```

### Examples

```bash
# Mount the filesystem DMG from an IPSW
$ ipsw mount fs iPhone15,2_16.5_20F66_Restore.ipsw

# Mount the system DMG with a specific decryption key
$ ipsw mount sys iPhone.ipsw --key "a1b2c3d4e5f6..."

# Mount fs DMG and lookup keys from theapplewiki.com
$ ipsw mount fs iPod5,1_7.1.2_11D257_Restore.ipsw --lookup

# Mount dyld shared cache (exc) DMG with AEA pem DB
$ ipsw mount exc iPhone.ipsw --pem-db /path/to/pem.json

```

### Options

```
  -h, --help            help for mount
  -k, --key string      DMG key
      --lookup          Lookup DMG keys on theapplewiki.com
      --pem-db string   AEA pem DB JSON file
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

