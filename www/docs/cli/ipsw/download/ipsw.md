---
id: ipsw
title: ipsw
hide_title: true
hide_table_of_contents: true
sidebar_label: ipsw
description: Download and parse IPSW(s) from ipsw.me
---
## ipsw download ipsw

Download and parse IPSW(s) from ipsw.me

```
ipsw download ipsw [flags]
```

### Examples

```bash
# Download latest iOS IPSWs for iPhone15,2
❯ ipsw download ipsw --device iPhone15,2 --latest

# Download specific iOS build with kernelcache extraction
❯ ipsw download ipsw --device iPhone14,2 --build 20G75 --kernel

# Extract a device-specific macOS cache without filtering the feed by device
❯ ipsw download ipsw --macos --version 27.0 --dyld --extract-device Mac18,5

# Get URLs only without downloading
❯ ipsw download ipsw --device iPhone15,2 --version 17.0 --urls

```

### Options

```
      --black-list stringArray             iOS device black list
  -b, --build string                       iOS BuildID (i.e. 16F203)
  -y, --confirm[=true|false]               do not prompt user for confirmation
      --decrypt[=true|false]               Attempt to decrypt the partial files if keys are available
  -d, --device string                      iOS Device (i.e. iPhone11,2)
      --dyld[=true|false]                  Extract dyld_shared_cache(s) from remote IPSW
  -a, --dyld-arch stringArray              dyld_shared_cache architecture(s) to remote extract
      --extract-device string              Product type or board for partial extraction (does not filter the download feed)
      --fcs-keys[=true|false]              Download AEA1 DMG fcs-key pem files
      --fcs-keys-json[=true|false]         Download AEA1 DMG fcs-keys as JSON
  -f, --flat[=true|false]                  Do NOT preserve directory structure when downloading with --pattern
  -h, --help[=true|false]                  help for ipsw
      --ibridge[=true|false]               Download iBridge IPSWs
      --ignore-sha1[=true|false]           skip checksum verification
      --insecure[=true|false]              do not verify ssl certs
      --kernel[=true|false]                Extract kernelcache from remote IPSW
      --latest[=true|false]                Download latest IPSWs
      --macos[=true|false]                 Download macOS IPSWs
  -m, --model string                       iOS Model (i.e. D321AP)
  -o, --output string                      Folder to download files to
      --pattern string                     Download remote files that match regex
      --proxy string                       HTTP/HTTPS proxy
  -_, --remove-commas[=true|false]         replace commas in IPSW filename with underscores
      --restart-all[=true|false]           always restart resumable IPSWs
      --show-latest-build[=true|false]     Show latest iOS build
      --show-latest-version[=true|false]   Show latest iOS version
      --skip-all[=true|false]              continue past files locked by another download process
  -u, --urls[=true|false]                  Dump URLs only
      --usb[=true|false]                   Download IPSWs for USB attached iDevices
  -v, --version string                     iOS Version (i.e. 12.3.1)
      --white-list stringArray             iOS device white list
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

