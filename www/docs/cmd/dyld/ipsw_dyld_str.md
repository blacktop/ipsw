---
date: 2022-11-20T23:11:40-07:00
title: "ipsw dyld str"
slug: ipsw_dyld_str
url: /commands/ipsw_dyld_str/
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
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/cmd/ipsw_dyld/)	 - Parse dyld_shared_cache

