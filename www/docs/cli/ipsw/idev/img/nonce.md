---
id: nonce
title: nonce
hide_title: true
hide_table_of_contents: true
sidebar_label: nonce
description: Query Nonce
---
## ipsw idev img nonce

Query Nonce

```
ipsw idev img nonce [flags]
```

### Options

```
  -h, --help             help for nonce
  -j, --json             Print as JSON
  -m, --mail string      QR mailto address
  -o, --output string    Folder to write QR code PNG to
  -q, --qr-code          Generate QR code of nonce
  -z, --qr-size int      QR size in pixels (default 256)
  -r, --readable         Print nonce as a more readable string
  -s, --subject string   QR mailto subject (default "Device Nonce Info")
      --url string       QR code URL
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -u, --udid string     Device UniqueDeviceID to connect to
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw idev img](/docs/cli/ipsw/idev/img)	 - Image commands

