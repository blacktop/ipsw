---
id: objc
title: objc
hide_title: true
hide_table_of_contents: true
sidebar_label: objc
description: Dump Objective-C Optimization Info
last_update:
  date: 2022-12-10T13:19:31-07:00
  author: blacktop
---
## ipsw dyld objc

Dump Objective-C Optimization Info

```
ipsw dyld objc <dyld_shared_cache> [flags]
```

### Options

```
  -c, --class       Print the classes
  -h, --help        help for objc
  -i, --imp-cache   Print the imp-caches
  -p, --proto       Print the protocols
  -s, --sel         Print the selectors
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache
* [ipsw dyld objc class](/docs/cli/ipsw/dyld/objc/class)	 - Get ObjC class info
* [ipsw dyld objc proto](/docs/cli/ipsw/dyld/objc/proto)	 - Get ObjC proto info
* [ipsw dyld objc sel](/docs/cli/ipsw/dyld/objc/sel)	 - Get ObjC selector info

