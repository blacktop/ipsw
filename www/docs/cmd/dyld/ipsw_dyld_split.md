---
date: 2022-11-20T23:11:40-07:00
title: "ipsw dyld split"
slug: ipsw_dyld_split
url: /commands/ipsw_dyld_split/
---
## ipsw dyld split

Extracts all the dyld_shared_cache libraries

```
ipsw dyld split <dyld_shared_cache> <optional_output_path> [flags]
```

### Options

```
  -b, --build string     Cache build
  -c, --cache            Build XCode device support cache
  -h, --help             help for split
  -v, --version string   Cache version
  -x, --xcode string     Path to Xcode.app
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/cmd/ipsw_dyld/)	 - Parse dyld_shared_cache

