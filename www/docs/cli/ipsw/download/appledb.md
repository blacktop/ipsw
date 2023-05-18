---
id: appledb
title: appledb
hide_title: true
hide_table_of_contents: true
sidebar_label: appledb
description: Download IPSWs from appledb
---
## ipsw download appledb

Download IPSWs from appledb

```
ipsw download appledb [flags]
```

### Examples

```bash
  # Download the iOS 16.5 beta 4 kernelcache from remote IPSW
  ❯ ipsw download appledb --os iOS --version '16.5 beta 4' --device iPhone15,2 --kernel
   • Querying AppleDB...
   • Parsing remote IPSW       build=20F5059a devices=iPhone15,2 version=16.5
   • Extracting remote kernelcache
      • Writing 20F5059a__iPhone15,2/kernelcache.release.iPhone15,2
```

### Options

```
      --beta             Download beta IPSWs
  -f, --flat             Do NOT perserve directory structure when downloading with --pattern
  -h, --help             help for appledb
      --kernel           Extract kernelcache from remote IPSW
      --os string        Operating system to download (i.e. iOS, tvOS, watchOS, bridgeOS)
  -o, --output string    Folder to download files to
      --pattern string   Download remote files that match regex
```

### Options inherited from parent commands

```
      --black-list stringArray   iOS device black list
  -b, --build string             iOS BuildID (i.e. 16F203)
      --color                    colorize output
      --config string            config file (default is $HOME/.config/ipsw/config.yaml)
  -y, --confirm                  do not prompt user for confirmation
  -d, --device string            iOS Device (i.e. iPhone11,2)
      --insecure                 do not verify ssl certs
  -m, --model string             iOS Model (i.e. D321AP)
      --proxy string             HTTP/HTTPS proxy
  -_, --remove-commas            replace commas in IPSW filename with underscores
      --restart-all              always restart resumable IPSWs
      --resume-all               always resume resumable IPSWs
      --skip-all                 always skip resumable IPSWs
  -V, --verbose                  verbose output
  -v, --version string           iOS Version (i.e. 12.3.1)
      --white-list stringArray   iOS device white list
```

### SEE ALSO

* [ipsw download](/docs/cli/ipsw/download)	 - Download Apple Firmware files (and more)

