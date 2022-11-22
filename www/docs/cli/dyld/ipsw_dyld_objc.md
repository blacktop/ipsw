---
id: ipsw_dyld_objc
title: ipsw dyld objc
hide_title: true
sidebar_label: objc
description: Dump Objective-C Optimization Info
last_update:
  date: 2022-11-21T19:10:35-07:00
  author: blacktop
---
# ipsw dyld objc

Dump Objective-C Optimization Info

```
ipsw dyld objc <dyld_shared_cache> [flags]
```

## Options

```
  -c, --class       Print the classes
  -h, --help        help for objc
  -i, --imp-cache   Print the imp-caches
  -p, --proto       Print the protocols
  -s, --sel         Print the selectors
```

## Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

## See also

* [ipsw dyld](/docs/cli/dyld/ipsw_dyld)	 - Parse dyld_shared_cache
* [ipsw dyld objc class](/docs/cli/dyld/ipsw_dyld_objc_class)	 - Get ObjC class info
* [ipsw dyld objc proto](/docs/cli/dyld/ipsw_dyld_objc_proto)	 - Get ObjC proto info
* [ipsw dyld objc sel](/docs/cli/dyld/ipsw_dyld_objc_sel)	 - Get ObjC selector info

