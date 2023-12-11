---
id: ssh
title: ssh
hide_title: true
hide_table_of_contents: true
sidebar_label: ssh
description: SSH into a jailbroken device
---
## ipsw ssh

SSH into a jailbroken device

```
ipsw ssh [flags]
```

### Options

```
  -h, --help              help for ssh
  -t, --host string       ssh host (default "localhost")
  -n, --insecure          ignore known_hosts
  -i, --key string        ssh key (default "$HOME/.ssh/id_rsa")
  -s, --password string   ssh password (default "alpine")
  -p, --port string       ssh port (default "2222")
  -u, --user string       ssh user (default "root")
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)
* [ipsw ssh debugserver](/docs/cli/ipsw/ssh/debugserver)	 - Prep device for remote debugging
* [ipsw ssh shsh](/docs/cli/ipsw/ssh/shsh)	 - Get shsh blobs from device

