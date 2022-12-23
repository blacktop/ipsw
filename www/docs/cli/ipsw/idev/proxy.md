---
id: proxy
title: proxy
hide_title: true
hide_table_of_contents: true
sidebar_label: proxy
description: Create a TCP proxy (for ssh/debugging)
last_update:
  date: 2022-12-23T02:36:33-07:00
  author: blacktop
---
## ipsw idev proxy

Create a TCP proxy (for ssh/debugging)

```
ipsw idev proxy [flags]
```

### Options

```
  -h, --help        help for proxy
  -l, --lport int   host port
  -r, --rport int   device port
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -u, --udid string     Device UniqueDeviceID to connect to
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw idev](/docs/cli/ipsw/idev)	 - USB connected device commands

