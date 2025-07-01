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

### Examples

```bash
# Download older IPSWs for specific device
❯ ipsw download wiki --ipsw --device iPhone10,6 --version 12.0

# Download OTA updates with prerequisites
❯ ipsw download wiki --ota --device iPhone14,2 --version 17.1 --pv 17.0

# Extract kernelcache from remote IPSW
❯ ipsw download wiki --ipsw --device iPhone14,2 --build 21A329 --kernel

# Build JSON database of firmware metadata
❯ ipsw download wiki --ipsw --device iPhone14,2 --json

```

### Options

```
      --beta             Download beta IPSWs/OTAs
  -b, --build string     iOS BuildID (i.e. 16F203)
  -y, --confirm          do not prompt user for confirmation
      --db string        Path to local JSON database (will use CWD by default) (default "wiki_db.json")
  -d, --device string    iOS Device (i.e. iPhone11,2)
  -f, --flat             Do NOT perserve directory structure when downloading with --pattern
  -h, --help             help for wiki
      --insecure         do not verify ssl certs
      --ipsw             Download IPSWs
      --json             Parse URLs and store metadata in local JSON database
      --kernel           Extract kernelcache from remote IPSW
      --ota              Download OTAs
  -o, --output string    Folder to download files to
      --pattern string   Download remote files that match regex
      --pb string        OTA prerequisite build
      --proxy string     HTTP/HTTPS proxy
      --pv string        OTA prerequisite version
  -_, --remove-commas    replace commas in IPSW filename with underscores
      --restart-all      always restart resumable IPSWs
      --resume-all       always resume resumable IPSWs
      --skip-all         always skip resumable IPSWs
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

