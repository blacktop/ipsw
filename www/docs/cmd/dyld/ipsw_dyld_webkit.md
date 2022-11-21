---
date: 2022-11-20T23:11:40-07:00
title: "ipsw dyld webkit"
slug: ipsw_dyld_webkit
url: /commands/ipsw_dyld_webkit/
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
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/cmd/ipsw_dyld/)	 - Parse dyld_shared_cache

