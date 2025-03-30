---
id: appstore
title: appstore
hide_title: true
hide_table_of_contents: true
sidebar_label: appstore
description: Interact with the App Store Connect API
---
## ipsw appstore

Interact with the App Store Connect API

```
ipsw appstore [flags]
```

### Options

```
  -h, --help         help for appstore
  -i, --iss string   Issuer ID
  -j, --jwt string   JWT api key
  -k, --kid string   Key ID
  -p, --p8 string    Path to App Store Connect API Key (.p8)
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
* [ipsw appstore bundle](/docs/cli/ipsw/appstore/bundle)	 - Manage the bundle IDs that uniquely identify your apps
* [ipsw appstore cert](/docs/cli/ipsw/appstore/cert)	 - Create, download, and revoke signing certificates for app development and distribution
* [ipsw appstore device](/docs/cli/ipsw/appstore/device)	 - Register devices for development and testing
* [ipsw appstore profile](/docs/cli/ipsw/appstore/profile)	 - Create, delete, and download provisioning profiles that enable app installations for development and distribution
* [ipsw appstore provision](/docs/cli/ipsw/appstore/provision)	 - Provision system for Xcode code signing
* [ipsw appstore review-list](/docs/cli/ipsw/appstore/review-list)	 - List app store reviews
* [ipsw appstore token](/docs/cli/ipsw/appstore/token)	 - Generate JWT for AppStore Connect API

