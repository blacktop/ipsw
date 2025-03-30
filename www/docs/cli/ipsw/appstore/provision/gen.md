---
id: gen
title: gen
hide_title: true
hide_table_of_contents: true
sidebar_label: gen
description: Download/Create priv key, certificate & provisioning profile for Xcode signing
---
## ipsw appstore provision gen

Download/Create priv key, certificate & provisioning profile for Xcode signing

### Synopsis

Downloads or creates the necessary certificate and provisioning profile
from App Store Connect for a given bundle ID, based on the specified type
(development, adhoc, distribution). It then optionally installs them locally
for Xcode code signing.

```
ipsw appstore provision gen <BUNDLE_ID> [flags]
```

### Options

```
  -c, --country string   Country code for certificate subject (e.g., US, GB) (default "US")
      --csr              Create a NEW Certificate Signing Request
  -e, --email string     Email address to use for the certificate
  -h, --help             help for gen
      --install          Install the certificate and profile
  -o, --output string    Folder to save files to
  -t, --type string      Type of profile to manage (development, adhoc, distribution) (default "development")
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

* [ipsw appstore provision](/docs/cli/ipsw/appstore/provision)	 - Provision system for Xcode code signing

