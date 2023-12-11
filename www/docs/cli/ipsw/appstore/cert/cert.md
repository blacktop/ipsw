---
id: cert
title: cert
hide_title: true
hide_table_of_contents: true
sidebar_label: cert
description: Create, download, and revoke signing certificates for app development and distribution
---
## ipsw appstore cert

Create, download, and revoke signing certificates for app development and distribution

```
ipsw appstore cert [flags]
```

### Options

```
  -h, --help   help for cert
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
* [ipsw appstore cert add](/docs/cli/ipsw/appstore/cert/add)	 - Create a new certificate using a certificate signing request
* [ipsw appstore cert ls](/docs/cli/ipsw/appstore/cert/ls)	 - List certificates
* [ipsw appstore cert rm](/docs/cli/ipsw/appstore/cert/rm)	 - Revoke a lost, stolen, compromised, or expiring signing certificate

