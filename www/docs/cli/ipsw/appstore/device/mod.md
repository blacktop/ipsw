---
id: mod
title: mod
hide_title: true
hide_table_of_contents: true
sidebar_label: mod
description: Register a new device for app development
---
## ipsw appstore device mod

Register a new device for app development

```
ipsw appstore device mod [flags]
```

### Options

```
  -h, --help            help for mod
      --id string       Device ID
  -n, --name string     Device name
  -s, --status string   Device status (ENABLED|DISABLED)) (default "ENABLED")
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
  -i, --iss string      Issuer ID
  -j, --jwt string      JWT api key
  -k, --kid string      Key ID
      --no-color        disable colorize output
  -p, --p8 string       Path to App Store Connect API Key (.p8)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw appstore device](/docs/cli/ipsw/appstore/device)	 - Register devices for development and testing

