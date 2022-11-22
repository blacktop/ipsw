---
id: ipsw_dyld_str
title: ipsw dyld str
hide_title: true
sidebar_label: str
description: Search dyld_shared_cache for string
last_update:
  date: 2022-11-21T19:10:35-07:00
  author: blacktop
---
# ipsw dyld str

Search dyld_shared_cache for string

```
ipsw dyld str <dyld_shared_cache> <string> [flags]
```

## Options

```
  -c, --contains         Match strings that contain the search substring
  -h, --help             help for str
  -i, --insensitive      Case-insensitive search
  -p, --pattern string   Regex match strings (FAST)
```

## Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

## See also

* [ipsw dyld](/docs/cli/dyld/ipsw_dyld)	 - Parse dyld_shared_cache

