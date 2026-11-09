---
id: token
title: token
hide_title: true
hide_table_of_contents: true
sidebar_label: token
description: Generate JWT for AppStore Connect API
---
## ipsw appstore token

Generate JWT for AppStore Connect API

```
ipsw appstore token [flags]
```

### Options

```
  -h, --help[=true|false]   help for token
  -l, --lifetime duration   Lifetime of JWT (max: 20m) (default 5m0s)
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

* [ipsw appstore](/docs/cli/ipsw/appstore)	 - Interact with the App Store Connect API

