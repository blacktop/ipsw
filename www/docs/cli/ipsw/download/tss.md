---
id: tss
title: tss
hide_title: true
hide_table_of_contents: true
sidebar_label: tss
description: 🚧 Download SHSH Blobs
---
## ipsw download tss

🚧 Download SHSH Blobs

```
ipsw download tss [flags]
```

### Examples

```bash
# Check if iOS version is still being signed
❯ ipsw download tss --device iPhone14,2 --version 17.0 --signed

# Check signing status for USB connected device
❯ ipsw download tss --usb --signed

# Download SHSH blobs for specific device/version (WIP)
❯ ipsw download tss --device iPhone14,2 --version 17.0

```

### Options

```
  -b, --build string     iOS BuildID (i.e. 16F203)
  -d, --device string    iOS Device (i.e. iPhone11,2)
  -h, --help             help for tss
      --insecure         do not verify ssl certs
      --proxy string     HTTP/HTTPS proxy
  -s, --signed           Check if iOS version is still being signed
  -u, --usb              Download blobs for USB connected device
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

