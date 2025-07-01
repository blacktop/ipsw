---
id: kdk
title: kdk
hide_title: true
hide_table_of_contents: true
sidebar_label: kdk
description: Download KDKs
---
## ipsw download kdk

Download KDKs

```
ipsw download kdk [flags]
```

### Examples

```bash
# Download KDK for current host OS
❯ ipsw download kdk --host

# Download KDK for specific build
❯ ipsw download kdk --build 20G75

# Download latest KDK and install
❯ ipsw download kdk --latest --install

# Download all available KDKs
❯ ipsw download kdk --all

```

### Options

```
  -a, --all             Download all KDKs
  -b, --build string    Download KDK for build
  -h, --help            help for kdk
      --host            Download KDK for current host OS
      --insecure        do not verify ssl certs
  -i, --install         Install KDK after download
  -l, --latest          Download latest KDK
  -o, --output string   Folder to download files to
      --proxy string    HTTP/HTTPS proxy
      --restart-all     always restart resumable IPSWs
      --resume-all      always resume resumable IPSWs
      --skip-all        always skip resumable IPSWs
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw download](/docs/cli/ipsw/download)	 - Download Apple Firmware files (and more)

