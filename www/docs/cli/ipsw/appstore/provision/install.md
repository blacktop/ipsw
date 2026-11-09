---
id: install
title: install
hide_title: true
hide_table_of_contents: true
sidebar_label: install
description: Install private key, certificate & provisioning profile for Xcode signing
---
## ipsw appstore provision install

Install private key, certificate & provisioning profile for Xcode signing

```
ipsw appstore provision install <CERT> <KEY> <PROFILE> [flags]
```

### Options

```
  -h, --help[=true|false]   help for install
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
  -i, --iss string              Issuer ID
  -j, --jwt string              JWT api key
  -k, --kid string              Key ID
      --no-color[=true|false]   disable colorize output
  -p, --p8 string               Path to App Store Connect API Key (.p8)
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw appstore provision](/docs/cli/ipsw/appstore/provision)	 - Provision system for Xcode code signing

