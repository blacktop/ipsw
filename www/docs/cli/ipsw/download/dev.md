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
  -b, --build string            iOS BuildID (i.e. 16F203)
  -h, --help                    help for dev
      --insecure                do not verify ssl certs
      --json                    Output downloadable items as JSON
      --more                    Download 'More' OSes/Apps
      --os                      Download '*OS' OSes/Apps
  -o, --output string           Folder to download files to
      --page int                Page size for file lists (default 20)
  -p, --password string         Apple Developer Portal password
      --pretty                  Pretty print JSON
      --profile                 Download Logging Profiles
      --proxy string            HTTP/HTTPS proxy
  -_, --remove-commas           replace commas in IPSW filename with underscores
      --restart-all             always restart resumable IPSWs
      --resume-all              always resume resumable IPSWs
      --skip-all                always skip resumable IPSWs
      --sms                     Prefer SMS Two-factor authentication
  -t, --timeout duration        Timeout for watch attempts in minutes (default 5m0s)
  -u, --username string         Apple Developer Portal username
  -k, --vault-password string   Password to unlock credential vault (only for file vaults)
  -v, --version string          iOS Version (i.e. 12.3.1)
  -w, --watch stringArray       Developer portal group pattern to watch (i.e. '^iOS.*beta$')
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

