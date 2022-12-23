---
id: str
title: str
hide_title: true
hide_table_of_contents: true
sidebar_label: str
description: Search dyld_shared_cache for string
last_update:
  date: 2022-12-23T02:36:33-07:00
  author: blacktop
---
## ipsw dyld str

Search dyld_shared_cache for string

```
ipsw dyld str <dyld_shared_cache> <string> [flags]
```

### Options

```
  -c, --contains         Match strings that contain the search substring
  -h, --help             help for str
  -i, --insensitive      Case-insensitive search
  -p, --pattern string   Regex match strings (FAST)
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

