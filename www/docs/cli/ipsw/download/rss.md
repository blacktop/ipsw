---
id: rss
title: rss
hide_title: true
hide_table_of_contents: true
sidebar_label: rss
description: Read Releases - Apple Developer RSS Feed
---
## ipsw download rss

Read Releases - Apple Developer RSS Feed

```
ipsw download rss [flags]
```

### Examples

```bash
# Read latest Apple developer releases
❯ ipsw download rss

# Watch for new releases with notifications
❯ ipsw download rss --watch

# Output RSS feed as JSON
❯ ipsw download rss --json

```

### Options

```
  -h, --help    help for rss
  -j, --json    Output as JSON
  -w, --watch   Watch for NEW releases
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

