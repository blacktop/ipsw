---
id: wiki
title: wiki
hide_title: true
hide_table_of_contents: true
sidebar_label: wiki
description: Download old(er) IPSWs from theiphonewiki.com
---
## ipsw download wiki

Download old(er) IPSWs from theiphonewiki.com

```
ipsw download wiki [flags]
```

### Options

```
      --beta             Download beta IPSWs/OTAs
      --db string        Path to local JSON database (will use CWD by default) (default "wiki_db.json")
  -f, --flat             Do NOT perserve directory structure when downloading with --pattern
  -h, --help             help for wiki
      --ipsw             Download IPSWs
      --json             Parse URLs and store metadata in local JSON database
      --kernel           Extract kernelcache from remote IPSW
      --ota              Download OTAs
  -o, --output string    Folder to download files to
      --pattern string   Download remote files that match regex
      --pb string        OTA prerequisite build
      --pv string        OTA prerequisite version
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

