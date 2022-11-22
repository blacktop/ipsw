---
id: ipsw_idev_img_mount
title: ipsw idev img mount
hide_title: true
sidebar_label: mount
description: Mount an image
last_update:
  date: 2022-11-21T19:10:35-07:00
  author: blacktop
---
## ipsw idev img mount

Mount an image

```
ipsw idev img mount <image> <signature> [flags]
```

### Options

```
  -h, --help                help for mount
  -t, --image-type string   Image type to mount (default "Developer")
  -x, --xcode string        Path to Xcode.app (default "/Applications/Xcode.app")
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -u, --udid string     Device UniqueDeviceID to connect to
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw idev img](/docs/cli/img/ipsw_idev_img)	 - Image commands

