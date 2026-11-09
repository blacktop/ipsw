---
id: shsh
title: shsh
hide_title: true
hide_table_of_contents: true
sidebar_label: shsh
description: Get SHSH blobs from device
---
## ipsw ssh shsh

Get SHSH blobs from device

```
ipsw ssh shsh [flags]
```

### Options

```
  -h, --help[=true|false]   help for shsh
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
  -t, --host string             ssh host (default "localhost")
  -n, --insecure[=true|false]   ignore known_hosts
  -i, --key string              ssh key (e.g. ~/.ssh/id_rsa)
      --no-color[=true|false]   disable colorize output
  -s, --password string         ssh password (default "alpine")
  -p, --port string             ssh port (default "2222")
  -u, --user string             ssh user (default "root")
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw ssh](/docs/cli/ipsw/ssh)	 - SSH into a jailbroken device

