---
id: keys
title: keys
hide_title: true
hide_table_of_contents: true
sidebar_label: keys
description: Download FW keys from The iPhone Wiki
---
## ipsw download keys

Download FW keys from The iPhone Wiki

```
ipsw download keys [flags]
```

### Examples

```bash
# Download firmware keys for specific device/version
❯ ipsw download keys --device iPhone14,2 --version 17.0

# Download keys for specific build
❯ ipsw download keys --device iPhone14,2 --build 21A329

# Save keys as JSON file
❯ ipsw download keys --device iPhone14,2 --build 21A329 --output ./keys

# Output keys as JSON to stdout
❯ ipsw download keys --device iPhone14,2 --build 21A329 --json

```

### Options

```
  -b, --build string     iOS BuildID (i.e. 16F203)
  -d, --device string    iOS Device (i.e. iPhone11,2)
  -h, --help             help for keys
      --insecure         do not verify ssl certs
      --json             Output as JSON
  -o, --output string    Folder to download keys to
      --proxy string     HTTP/HTTPS proxy
  -v, --version string   iOS Version (i.e. 12.3.1)
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

