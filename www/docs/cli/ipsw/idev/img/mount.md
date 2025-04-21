---
id: mount
title: mount
hide_title: true
hide_table_of_contents: true
sidebar_label: mount
description: Mount an image
---
## ipsw idev img mount

Mount an image

```
ipsw idev img mount [flags]
```

### Options

```
  -d, --ddi-dmg string      DDI.dmg to mount
  -f, --ddi-folder string   DDI folder (i.e. /Library/Developer/DeveloperDiskImages/iOS_DDI)
  -h, --help                help for mount
  -t, --image-type string   Image type to mount (default "Personalized")
      --insecure            Do not verify ssl certs
  -m, --manifest string     BuildManifest.plist to use
      --proxy string        HTTP/HTTPS proxy
  -s, --signature string    Image signature to use
  -c, --trustcache string   Trustcache to use
  -x, --xcode string        Path to Xcode.app (i.e. /Applications/Xcode.app)
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

