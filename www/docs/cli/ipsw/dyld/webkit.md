---
id: webkit
title: webkit
hide_title: true
hide_table_of_contents: true
sidebar_label: webkit
description: Get WebKit version from a dyld_shared_cache
last_update:
  date: 2023-01-16T23:18:46-07:00
  author: blacktop
---
## ipsw dyld webkit

Get WebKit version from a dyld_shared_cache

```
ipsw dyld webkit <dyld_shared_cache> [flags]
```

### Options

```
  -a, --api string     Github API Token
  -g, --git            Lookup git tag on github.com
  -h, --help           help for webkit
      --insecure       do not verify ssl certs
      --proxy string   HTTP/HTTPS proxy
  -r, --rev            Lookup svn rev on trac.webkit.org
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

