---
id: tss
title: tss
hide_title: true
hide_table_of_contents: true
sidebar_label: tss
description: Check signing status and download SHSH blobs
---
## ipsw download tss

Check signing status and download SHSH blobs

```
ipsw download tss [flags]
```

### Examples

```bash
# Check if iOS version is still being signed
❯ ipsw download tss --device iPhone14,2 --version 17.0 --signed

# Check if latest iOS version is still being signed
❯ ipsw download tss --device iPhone14,2 --latest --signed

# Check signing status for USB connected device
❯ ipsw download tss --usb --signed

# Check signing status for a specific ECID
❯ ipsw download tss --device iPhone14,2 --version 17.0 --ecid 1234567890 --signed

# Download SHSH blobs for specific device/version
❯ ipsw download tss --device iPhone14,2 --version 17.0 --output 1234567890.shsh

```

### Options

```
      --beta             Check for beta iOS versions
  -b, --build string     iOS BuildID (i.e. 16F203)
  -d, --device string    iOS Device (i.e. iPhone11,2)
      --ecid uint        Device ECID
  -h, --help             help for tss
      --insecure         do not verify ssl certs
  -l, --latest           Check latest iOS version
  -o, --output string    Output path for SHSH blobs
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

