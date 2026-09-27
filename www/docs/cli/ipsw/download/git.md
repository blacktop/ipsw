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

### Synopsis

Download source tarballs using GitHub GraphQL, which requires authentication.
Token precedence: --api (or configured API token), GITHUB_TOKEN, GITHUB_API_TOKEN.
Select a repository with --product; positional arguments are not accepted.

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

# Download a specific product using the token already in GITHUB_TOKEN
❯ ipsw download git --product xnu

```

### Options

```
  -a, --api string       GitHub token (falls back to GITHUB_TOKEN, then GITHUB_API_TOKEN)
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
      --color                   colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --enable-node-selection   spread streams across CDN addresses by measured throughput
      --min-part-size int       minimum scheduler range size in MiB (0 uses the URL profile)
      --min-parts int           connections opened immediately and never retired (0 uses the URL profile)
      --no-color                disable colorize output
      --parts int               maximum parallel connections per download (0 uses the URL profile)
  -V, --verbose                 verbose output
```

### SEE ALSO

* [ipsw download](/docs/cli/ipsw/download)	 - Download Apple Firmware files (and more)

