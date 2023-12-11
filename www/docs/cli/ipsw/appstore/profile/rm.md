---
id: rm
title: rm
hide_title: true
hide_table_of_contents: true
sidebar_label: rm
description: Delete a provisioning profile that is used for app development or distribution
---
## ipsw appstore profile rm

Delete a provisioning profile that is used for app development or distribution

```
ipsw appstore profile rm [flags]
```

### Options

```
  -h, --help          help for rm
      --id string     Profile ID to renew
  -n, --name string   Profile name to renew
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

