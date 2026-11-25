---
id: setup
title: setup
hide_title: true
hide_table_of_contents: true
sidebar_label: setup
description: Prepare this Mac for IPA downloads
---
## ipsw download ipa setup

Prepare this Mac for IPA downloads

### Synopsis

Download Apple's support files (about 300 MB) and register this Mac with Apple.

The first download does this for you; run it yourself to prepare ahead of time.

```
ipsw download ipa setup [flags]
```

### Examples

```bash
# Download Apple's support files and register this Mac
❯ ipsw download ipa setup
```

### Options

```
  -h, --help[=true|false]   help for setup
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

* [ipsw download ipa](/docs/cli/ipsw/download/ipa)	 - Download App Packages from the iOS App Store

