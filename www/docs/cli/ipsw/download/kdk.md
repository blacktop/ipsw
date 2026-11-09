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

### Synopsis

Download KDKs. Without a selector, choose a KDK interactively.
Unattended use requires --host, --build, --latest, or --all.
After a successful --install, interactive sessions offer to delete the downloaded file.
Use --install --clean to delete it without prompting.

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

# Download, install, and delete the latest KDK installer
❯ ipsw download kdk --latest --install --clean

# Download all available KDKs
❯ ipsw download kdk --all

```

### Options

```
  -a, --all[=true|false]           Download all KDKs
  -b, --build string               Download KDK for build
      --clean[=true|false]         Delete downloaded KDK after successful installation
  -h, --help[=true|false]          help for kdk
      --host[=true|false]          Download KDK for current host OS
      --ignore-sha1[=true|false]   skip checksum verification
      --insecure[=true|false]      do not verify ssl certs
  -i, --install[=true|false]       Install KDK after download
  -l, --latest[=true|false]        Download latest KDK
  -o, --output string              Folder to download files to
      --proxy string               HTTP/HTTPS proxy
      --restart-all[=true|false]   always restart resumable IPSWs
      --skip-all[=true|false]      continue past files locked by another download process
```

### Options inherited from parent commands

```
      --color[=true|false]                   colorize output
      --config string                        config file (default is $HOME/.config/ipsw/config.yaml)
      --enable-node-selection[=true|false]   spread streams across CDN addresses by measured throughput
      --min-part-size int                    minimum scheduler range size in MiB (0 uses the URL profile)
      --min-parts int                        connections opened immediately and never retired (0 uses the URL profile)
      --no-color[=true|false]                disable colorize output
      --parts int                            maximum parallel connections per download (0 uses the URL profile)
  -V, --verbose[=true|false]                 verbose output
```

### SEE ALSO

* [ipsw download](/docs/cli/ipsw/download)	 - Download Apple Firmware files (and more)

