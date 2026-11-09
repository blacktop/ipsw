---
id: review-list
title: review-list
hide_title: true
hide_table_of_contents: true
sidebar_label: review-list
description: List app store reviews
---
## ipsw appstore review-list

List app store reviews

```
ipsw appstore review-list [flags]
```

### Options

```
      --after string        Only show responses on or after date, e.g. "2024-12-22"
  -h, --help[=true|false]   help for review-list
      --id string           App ID
      --since string        Only show responses within duration, e.g. "36h"
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

