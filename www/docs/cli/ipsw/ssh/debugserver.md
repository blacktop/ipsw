---
id: debugserver
title: debugserver
hide_title: true
hide_table_of_contents: true
sidebar_label: debugserver
description: Prep device for remote debugging
---
## ipsw ssh debugserver

Prep device for remote debugging

```
ipsw ssh debugserver [flags]
```

### Options

```
  -f, --force          overwrite file on device
  -h, --help           help for debugserver
  -m, --image string   path to DeveloperDiskImage.dmg
```

### Options inherited from parent commands

```
      --color             colorize output
      --config string     config file (default is $HOME/.config/ipsw/config.yaml)
  -t, --host string       ssh host (default "localhost")
  -n, --insecure          ignore known_hosts
  -i, --key string        ssh key (e.g. ~/.ssh/id_rsa)
      --no-color          disable colorize output
  -s, --password string   ssh password (default "alpine")
  -p, --port string       ssh port (default "2222")
  -u, --user string       ssh user (default "root")
  -V, --verbose           verbose output
```

### SEE ALSO

* [ipsw ssh](/docs/cli/ipsw/ssh)	 - SSH into a jailbroken device

