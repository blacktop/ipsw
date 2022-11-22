---
id: ipsw_idev_proxy
title: ipsw idev proxy
hide_title: true
sidebar_label: proxy
description: Create a TCP proxy (for ssh/debugging)
last_update:
  date: 2022-11-21T19:10:35-07:00
  author: blacktop
---
# ipsw idev proxy

Create a TCP proxy (for ssh/debugging)

```
ipsw idev proxy [flags]
```

## Options

```
  -h, --help        help for proxy
  -l, --lport int   host port
  -r, --rport int   device port
```

## Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -u, --udid string     Device UniqueDeviceID to connect to
  -V, --verbose         verbose output
```

## See also

* [ipsw idev](/docs/cli/idev/ipsw_idev)	 - USB connected device commands

