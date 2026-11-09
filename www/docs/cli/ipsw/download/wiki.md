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
      --beta[=true|false]            Download beta IPSWs/OTAs
  -b, --build string                 iOS BuildID (i.e. 16F203)
  -y, --confirm[=true|false]         do not prompt user for confirmation
      --db string                    Path to local JSON database (will use CWD by default) (default "wiki_db.json")
  -d, --device string                iOS Device (i.e. iPhone11,2)
  -f, --flat[=true|false]            Do NOT preserve directory structure when downloading with --pattern
  -h, --help[=true|false]            help for wiki
      --ignore-sha1[=true|false]     skip checksum verification
      --insecure[=true|false]        do not verify ssl certs
      --ipsw[=true|false]            Download IPSWs
      --json[=true|false]            Parse URLs and store metadata in local JSON database
      --kernel[=true|false]          Extract kernelcache from remote IPSW
      --ota[=true|false]             Download OTAs
  -o, --output string                Folder to download files to
      --pattern string               Download remote files that match regex
      --pb string                    OTA prerequisite build
      --proxy string                 HTTP/HTTPS proxy
      --pv string                    OTA prerequisite version
  -_, --remove-commas[=true|false]   replace commas in IPSW filename with underscores
      --restart-all[=true|false]     always restart resumable IPSWs
      --skip-all[=true|false]        continue past files locked by another download process
  -v, --version string               iOS Version (i.e. 12.3.1)
```

### Options inherited from parent commands

```
      --color[=true|false]                   colorize output
      --config string                        config file (default is $HOME/.config/ipsw/config.yaml)
      --enable-node-selection[=true|false]   spread streams across CDN addresses by measured throughput
      --min-part-size int                    minimum scheduler range size in MiB (0 uses the URL profile)
      --min-parts int                        connections opened immediately and never retired (0 uses the URL profile)
      --no-color[=true|false]                disable colorize output
      --parts int                            maximum parallel connections per download (0 uses the URL profile)
  -V, --verbose[=true|false]                 verbose output
```

### SEE ALSO

* [ipsw download](/docs/cli/ipsw/download)	 - Download Apple Firmware files (and more)

