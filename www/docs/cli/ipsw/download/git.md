---
id: git
title: git
hide_title: true
hide_table_of_contents: true
sidebar_label: git
description: Download github.com/orgs/apple-oss-distributions tarballs
---
## ipsw download git

Download github.com/orgs/apple-oss-distributions tarballs

```
ipsw download git [flags]
```

### Options

```
  -a, --api string       Github API Token
  -h, --help             help for git
      --json             Output downloadable tar.gz URLs as JSON
      --latest           Get ONLY latest tag
  -o, --output string    Folder to download files to
  -p, --product string   macOS product to download (i.e. dyld)
      --webkit           Get WebKit tags
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
      --no-color                 disable colorize output
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

