---
id: git
title: git
hide_title: true
hide_table_of_contents: true
sidebar_label: git
description: Download github.com/orgs/apple-oss-distributions tarballs
---
## ipsw download git

Download github.com/orgs/apple-oss-distributions tarballs

```
ipsw download git [flags]
```

### Examples

```bash
# Download latest dyld source tarballs
❯ ipsw download git --product dyld --latest

# Get all available tarballs as JSON
❯ ipsw download git --json --output ~/sources

# Download WebKit tags (not Apple OSS)
❯ ipsw download git --webkit --json

# Download specific product with API token
❯ ipsw download git --product xnu --api YOUR_TOKEN

```

### Options

```
  -a, --api string       Github API Token
  -h, --help             help for git
      --insecure         do not verify ssl certs
      --json             Output downloadable tar.gz URLs as JSON
      --latest           Get ONLY latest tag
  -o, --output string    Folder to download files to
  -p, --product string   macOS product to download (i.e. dyld)
      --proxy string     HTTP/HTTPS proxy
      --webkit           Get WebKit tags
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

