---
id: download
title: download
hide_title: true
hide_table_of_contents: true
sidebar_label: download
description: Download Apple Firmware files (and more)
---
## ipsw download

Download Apple Firmware files (and more)

```
ipsw download [flags]
```

### Options

```
      --black-list stringArray   iOS device black list
  -b, --build string             iOS BuildID (i.e. 16F203)
  -y, --confirm                  do not prompt user for confirmation
  -d, --device string            iOS Device (i.e. iPhone11,2)
  -h, --help                     help for download
      --insecure                 do not verify ssl certs
  -m, --model string             iOS Model (i.e. D321AP)
      --proxy string             HTTP/HTTPS proxy
  -_, --remove-commas            replace commas in IPSW filename with underscores
      --restart-all              always restart resumable IPSWs
      --resume-all               always resume resumable IPSWs
      --skip-all                 always skip resumable IPSWs
  -v, --version string           iOS Version (i.e. 12.3.1)
      --white-list stringArray   iOS device white list
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)
* [ipsw download appledb](/docs/cli/ipsw/download/appledb)	 - Download IPSWs from appledb
* [ipsw download dev](/docs/cli/ipsw/download/dev)	 - Download IPSWs (and more) from https://developer.apple.com/download
* [ipsw download git](/docs/cli/ipsw/download/git)	 - Download github.com/orgs/apple-oss-distributions tarballs
* [ipsw download ipa](/docs/cli/ipsw/download/ipa)	 - Download App Packages from the iOS App Store
* [ipsw download ipsw](/docs/cli/ipsw/download/ipsw)	 - Download and parse IPSW(s) from the internets
* [ipsw download keys](/docs/cli/ipsw/download/keys)	 - Download FW keys from The iPhone Wiki
* [ipsw download macos](/docs/cli/ipsw/download/macos)	 - Download macOS installers
* [ipsw download ota](/docs/cli/ipsw/download/ota)	 - Download OTAs
* [ipsw download rss](/docs/cli/ipsw/download/rss)	 - Read Releases - Apple Developer RSS Feed
* [ipsw download tss](/docs/cli/ipsw/download/tss)	 - 🚧 Download SHSH Blobs
* [ipsw download wiki](/docs/cli/ipsw/download/wiki)	 - Download old(er) IPSWs from theiphonewiki.com

