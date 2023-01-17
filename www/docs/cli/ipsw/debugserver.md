---
id: debugserver
title: debugserver
hide_title: true
hide_table_of_contents: true
sidebar_label: debugserver
description: Prep device for remote debugging
last_update:
  date: 2023-01-16T23:18:46-07:00
  author: blacktop
---
## ipsw debugserver

Prep device for remote debugging

```
ipsw debugserver [flags]
```

### Options

```
  -f, --force          overwrite file on device
  -h, --help           help for debugserver
  -t, --host string    ssh host (default "localhost")
  -m, --image string   path to DeveloperDiskImage.dmg
  -n, --insecure       ignore known_hosts key checking
  -i, --key string     ssh key (default "$HOME/.ssh/id_rsa")
  -p, --port string    ssh port (default "2222")
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

