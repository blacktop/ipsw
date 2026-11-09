---
id: image
title: image
hide_title: true
hide_table_of_contents: true
sidebar_label: image
description: Dump image array info
---
## ipsw dyld image

Dump image array info

```
ipsw dyld image <DSC> [DYLIB] [flags]
```

### Examples

```bash
  # List all the apps
  ❯ ipsw dyld image DSC
  # Dump the closure info for a in-cache dylib
  ❯ ipsw dyld image DSC Foundation
  # Dump the closure info for an app
  ❯ ipsw dyld image DSC /usr/libexec/timed
```

### Options

```
  -h, --help[=true|false]   help for image
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

