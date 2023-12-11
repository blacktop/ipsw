---
id: rm
title: rm
hide_title: true
hide_table_of_contents: true
sidebar_label: rm
description: Revoke a lost, stolen, compromised, or expiring signing certificate
---
## ipsw appstore cert rm

Revoke a lost, stolen, compromised, or expiring signing certificate

```
ipsw appstore cert rm [flags]
```

### Options

```
  -h, --help        help for rm
      --id string   Profile ID to renew
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

* [ipsw appstore cert](/docs/cli/ipsw/appstore/cert)	 - Create, download, and revoke signing certificates for app development and distribution

