---
id: sign
title: sign
hide_title: true
hide_table_of_contents: true
sidebar_label: sign
description: Personalize DDI
---
## ipsw idev img sign

Personalize DDI

```
ipsw idev img sign [flags]
```

### Options

```
  -b, --board-id uint     Device ApBoardID
  -c, --chip-id uint      Device ApChipID
  -e, --ecid uint         Device ApECID
  -h, --help              help for sign
      --insecure          do not verify ssl certs
  -m, --manifest string   BuildManifest.plist to use
  -n, --nonce string      Device ApNonce
  -o, --output string     Folder to write signature to
      --proxy string      HTTP/HTTPS proxy
  -x, --xcode string      Path to Xcode.app (default "/Applications/Xcode.app")
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
  -u, --udid string     Device UniqueDeviceID to connect to
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw idev img](/docs/cli/ipsw/idev/img)	 - Image commands

