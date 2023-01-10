---
id: split
title: split
hide_title: true
hide_table_of_contents: true
sidebar_label: split
description: Extracts all the dyld_shared_cache libraries
last_update:
  date: 2023-01-10T12:52:46-07:00
  author: blacktop
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
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

