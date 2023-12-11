---
id: update
title: update
hide_title: true
hide_table_of_contents: true
sidebar_label: update
description: Download an ipsw update if one exists
---
## ipsw update

Download an ipsw update if one exists

```
ipsw update [flags]
```

### Examples

```bash
# Grab an update for your platform
❯ ipsw update --detect
# Grab an update for another platform
❯ ipsw update --platform windows_x86_64
# Grab an update for your platform and overwrite the current one
❯ ipsw update --detect --replace
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
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

