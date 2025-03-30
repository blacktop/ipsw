---
id: provision
title: provision
hide_title: true
hide_table_of_contents: true
sidebar_label: provision
description: Provision system for Xcode code signing
---
## ipsw appstore provision

Provision system for Xcode code signing

```
ipsw appstore provision [flags]
```

### Options

```
  -h, --help   help for provision
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

* [ipsw appstore](/docs/cli/ipsw/appstore)	 - Interact with the App Store Connect API
* [ipsw appstore provision gen](/docs/cli/ipsw/appstore/provision/gen)	 - Download/Create priv key, certificate & provisioning profile for Xcode signing
* [ipsw appstore provision install](/docs/cli/ipsw/appstore/provision/install)	 - Install private key, certificate & provisioning profile for Xcode signing

