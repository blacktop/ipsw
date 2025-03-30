---
id: profile
title: profile
hide_title: true
hide_table_of_contents: true
sidebar_label: profile
description: Create, delete, and download provisioning profiles that enable app installations for development and distribution
---
## ipsw appstore profile

Create, delete, and download provisioning profiles that enable app installations for development and distribution

```
ipsw appstore profile [flags]
```

### Options

```
  -h, --help   help for profile
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
* [ipsw appstore profile create](/docs/cli/ipsw/appstore/profile/create)	 - Create a new provisioning profile
* [ipsw appstore profile info](/docs/cli/ipsw/appstore/profile/info)	 - Dump provisioning profile information
* [ipsw appstore profile ls](/docs/cli/ipsw/appstore/profile/ls)	 - List provisioning profiles and download their data
* [ipsw appstore profile renew](/docs/cli/ipsw/appstore/profile/renew)	 - Renew and expired or invalide provisioning profile
* [ipsw appstore profile rm](/docs/cli/ipsw/appstore/profile/rm)	 - Delete a provisioning profile that is used for app development or distribution

