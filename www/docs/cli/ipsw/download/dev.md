---
id: dev
title: dev
hide_title: true
hide_table_of_contents: true
sidebar_label: dev
description: Download IPSWs (and more) from the Apple Developer Portal
---
## ipsw download dev

Download IPSWs (and more) from the Apple Developer Portal

```
ipsw download dev [flags]
```

### Examples

```bash
# Download all available OSes interactively
❯ ipsw download dev --os

# Download logging profiles as JSON
❯ ipsw download dev --profile --json --pretty

# Watch for new releases matching pattern
❯ ipsw download dev --watch "^iOS.*beta$"

# Download more items (Xcode, KDKs, etc.)
❯ ipsw download dev --more --output ~/Downloads

```

### Options

```
  -b, --build string                 iOS BuildID (i.e. 16F203)
  -h, --help[=true|false]            help for dev
      --insecure[=true|false]        do not verify ssl certs
      --json[=true|false]            Output downloadable items as JSON
      --more[=true|false]            Download 'More' OSes/Apps
      --os[=true|false]              Download '*OS' OSes/Apps
  -o, --output string                Folder to download files to
      --page int                     Page size for file lists (default 20)
  -p, --password string              Apple Developer Portal password
      --pretty[=true|false]          Pretty print JSON
      --profile[=true|false]         Download Logging Profiles
      --proxy string                 HTTP/HTTPS proxy
  -_, --remove-commas[=true|false]   replace commas in IPSW filename with underscores
      --restart-all[=true|false]     always restart resumable IPSWs
      --skip-all[=true|false]        continue past files locked by another download process
      --sms[=true|false]             Prefer SMS Two-factor authentication
  -t, --timeout duration             Timeout for watch attempts in minutes (default 5m0s)
  -u, --username string              Apple Developer Portal username
  -k, --vault-password string        Password to unlock credential vault (only for file vaults)
  -v, --version string               iOS Version (i.e. 12.3.1)
  -w, --watch stringArray            Developer portal group pattern to watch (i.e. '^iOS.*beta$')
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

