---
id: shsh
title: shsh
hide_title: true
hide_table_of_contents: true
sidebar_label: shsh
description: Get shsh blobs from device
last_update:
  date: 2023-01-16T23:32:27-07:00
  author: blacktop
---
## ipsw shsh

Get shsh blobs from device

```
ipsw shsh [flags]
```

### Options

```
  -h, --help          help for shsh
  -t, --host string   ssh host (default "localhost")
  -n, --insecure      ignore known_hosts key checking
  -i, --key string    ssh key (default "$HOME/.ssh/id_rsa")
  -p, --port string   ssh port (default "2222")
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

