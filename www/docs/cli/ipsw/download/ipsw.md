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

# Get URLs only without downloading
❯ ipsw download ipsw --device iPhone15,2 --version 17.0 --urls

```

### Options

```
      --black-list stringArray   iOS device black list
  -b, --build string             iOS BuildID (i.e. 16F203)
  -y, --confirm                  do not prompt user for confirmation
      --decrypt                  Attempt to decrypt the partial files if keys are available
  -d, --device string            iOS Device (i.e. iPhone11,2)
      --dyld                     Extract dyld_shared_cache(s) from remote IPSW
  -a, --dyld-arch stringArray    dyld_shared_cache architecture(s) to remote extract
      --fcs-keys                 Download AEA1 DMG fcs-key pem files
      --fcs-keys-json            Download AEA1 DMG fcs-keys as JSON
  -f, --flat                     Do NOT perserve directory structure when downloading with --pattern
  -h, --help                     help for ipsw
      --ibridge                  Download iBridge IPSWs
      --insecure                 do not verify ssl certs
      --kernel                   Extract kernelcache from remote IPSW
      --latest                   Download latest IPSWs
      --macos                    Download macOS IPSWs
  -m, --model string             iOS Model (i.e. D321AP)
  -o, --output string            Folder to download files to
      --pattern string           Download remote files that match regex
      --proxy string             HTTP/HTTPS proxy
  -_, --remove-commas            replace commas in IPSW filename with underscores
      --restart-all              always restart resumable IPSWs
      --resume-all               always resume resumable IPSWs
      --show-latest-build        Show latest iOS build
      --show-latest-version      Show latest iOS version
      --skip-all                 always skip resumable IPSWs
  -u, --urls                     Dump URLs only
      --usb                      Download IPSWs for USB attached iDevices
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

* [ipsw download](/docs/cli/ipsw/download)	 - Download Apple Firmware files (and more)

