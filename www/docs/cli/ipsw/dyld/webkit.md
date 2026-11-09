---
id: webkit
title: webkit
hide_title: true
hide_table_of_contents: true
sidebar_label: webkit
description: Get WebKit version from a dyld_shared_cache
---
## ipsw dyld webkit

Get WebKit version from a dyld_shared_cache

### Synopsis

Get the WebKit version from a dyld_shared_cache. --diff requires two caches.
With --git, look for an exact source tag, otherwise report the greatest lower
available version as an unverified approximation. Without a GitHub token the
tag catalog is preprocessed and its freshness is unknown.

```
ipsw dyld webkit <DSC> [DSC] [flags]
```

### Options

```
  -a, --api string              Github API Token
  -d, --diff[=true|false]       Diff two dyld_shared_cache files
  -g, --git[=true|false]        Lookup git tag on github.com
  -h, --help[=true|false]       help for webkit
      --insecure[=true|false]   do not verify ssl certs
  -j, --json[=true|false]       Output as JSON
      --proxy string            HTTP/HTTPS proxy
  -r, --rev[=true|false]        Lookup svn rev on trac.webkit.org
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

