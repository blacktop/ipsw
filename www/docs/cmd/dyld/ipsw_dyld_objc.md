---
date: 2022-11-20T23:11:40-07:00
title: "ipsw dyld objc"
slug: ipsw_dyld_objc
url: /commands/ipsw_dyld_objc/
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

* [ipsw dyld](/cmd/ipsw_dyld/)	 - Parse dyld_shared_cache
* [ipsw dyld objc class](/cmd/ipsw_dyld_objc_class/)	 - Get ObjC class info
* [ipsw dyld objc proto](/cmd/ipsw_dyld_objc_proto/)	 - Get ObjC proto info
* [ipsw dyld objc sel](/cmd/ipsw_dyld_objc_sel/)	 - Get ObjC selector info

