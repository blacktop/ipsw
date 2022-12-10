---
id: dev
title: dev
hide_title: true
hide_table_of_contents: true
sidebar_label: dev
description: Download IPSWs (and more) from https://developer.apple.com/download
last_update:
  date: 2022-12-10T13:19:31-07:00
  author: blacktop
---
## ipsw download dev

Download IPSWs (and more) from https://developer.apple.com/download

```
ipsw download dev [flags]
```

### Options

```
  -h, --help                help for dev
      --json                Output downloadable items as JSON
      --more                Download 'More' OSs/Apps
  -o, --output string       Folder to download files to
  -p, --page int            Page size for file lists (default 20)
      --pretty              Pretty print JSON
      --sms                 Prefer SMS Two-factor authentication
      --watch stringArray   dev portal type to watch
```

### Options inherited from parent commands

```
      --black-list stringArray   iOS device black list
  -b, --build string             iOS BuildID (i.e. 16F203)
      --color                    colorize output
      --config string            config file (default is $HOME/.ipsw.yaml)
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

