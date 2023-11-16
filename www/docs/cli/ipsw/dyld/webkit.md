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

```
ipsw dyld webkit <DSC> [flags]
```

### Options

```
  -a, --api string     Github API Token
  -d, --diff           Diff two dyld_shared_cache files
  -g, --git            Lookup git tag on github.com
  -h, --help           help for webkit
      --insecure       do not verify ssl certs
  -j, --json           Output as JSON
      --proxy string   HTTP/HTTPS proxy
  -r, --rev            Lookup svn rev on trac.webkit.org
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

