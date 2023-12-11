---
id: create
title: create
hide_title: true
hide_table_of_contents: true
sidebar_label: create
description: Create a new provisioning profile
---
## ipsw appstore profile create

Create a new provisioning profile

```
ipsw appstore profile create <NAME> [flags]
```

### Options

```
  -b, --bundle-id string   Board ID
  -c, --certs strings      Certificate IDs
  -d, --devices strings    Device IDs
  -h, --help               help for create
  -o, --output string      Folder to download profile to
  -t, --type string        Profile type (default "IOS_APP_DEVELOPMENT")
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

