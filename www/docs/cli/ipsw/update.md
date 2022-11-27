---
id: update
title: update
hide_title: true
hide_table_of_contents: true
sidebar_label: update
description: Download an ipsw update if one exists
last_update:
  date: 2022-11-26T17:29:41-07:00
  author: blacktop
---
## ipsw update

Download an ipsw update if one exists

```
ipsw update [flags]
```

### Options

```
  -a, --api string        Github API Token (incase you get rate limited)
      --detect            detect my platform
  -h, --help              help for update
      --insecure          do not verify ssl certs
  -p, --platform string   ipsw platform binary to update
      --proxy string      HTTP/HTTPS proxy
      --replace           overwrite current ipsw
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

