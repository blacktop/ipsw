---
id: renew
title: renew
hide_title: true
hide_table_of_contents: true
sidebar_label: renew
description: Renew and expired or invalide provisioning profile
---
## ipsw appstore profile renew

Renew and expired or invalide provisioning profile

```
ipsw appstore profile renew <NAME> [flags]
```

### Options

```
  -h, --help            help for renew
      --id string       Profile ID to renew
  -n, --name string     Profile name to renew
  -o, --output string   Folder to download profile to
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

* [ipsw appstore profile](/docs/cli/ipsw/appstore/profile)	 - Create, delete, and download provisioning profiles that enable app installations for development and distribution

