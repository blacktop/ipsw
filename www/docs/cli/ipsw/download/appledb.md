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

# Download latest release iOS IPSWs for multiple devices
❯ ipsw download appledb --os iOS --latest --release

# Get URLs only for beta macOS IPSWs
❯ ipsw download appledb --os macOS --beta --urls --json

# Download OTA deltas for specific build
❯ ipsw download appledb --os iOS --type ota --deltas --prereq-build 20G75

```

### Options

```
  -a, --api                   Use Github API
      --api-token string      Github API Token
      --beta                  Download beta IPSWs
  -b, --build string          iOS BuildID (i.e. 16F203)
  -y, --confirm               do not prompt user for confirmation
      --deltas                Download all OTA deltas
  -d, --device string         iOS Device (i.e. iPhone11,2)
      --dyld                  Extract dyld_shared_cache(s) from remote OTA
      --fcs-keys              Download AEA1 DMG fcs-key pem files
      --fcs-keys-json         Download AEA1 DMG fcs-keys as JSON
  -f, --flat                  Do NOT perserve directory structure when downloading with --pattern
  -h, --help                  help for appledb
      --insecure              do not verify ssl certs
  -j, --json                  Dump DB query results as JSON
      --kernel                Extract kernelcache from remote IPSW
      --latest                Download latest IPSWs
      --os stringArray        Operating system to download (audioOS, bridgeOS, iOS, iPadOS, iPodOS, macOS, tvOS, watchOS, visionOS)
  -o, --output string         Folder to download files to
      --pattern string        Download remote files that match regex
  -p, --prereq-build string   OTA prerequisite build
      --proxy string          HTTP/HTTPS proxy
      --rc                    Download RC (release candidate) IPSWs
      --release               Download release IPSWs
  -_, --remove-commas         replace commas in IPSW filename with underscores
      --restart-all           always restart resumable IPSWs
      --resume-all            always resume resumable IPSWs
      --show-latest           Show latest version/build
      --skip-all              always skip resumable IPSWs
      --type string           FW type to download (ipsw, ota, rsr) (default "ipsw")
  -u, --urls                  Dump URLs only
      --usb                   Download IPSWs for USB attached iDevices
  -v, --version string        iOS Version (i.e. 12.3.1)
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

