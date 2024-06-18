---
id: ipsw
title: ipsw
hide_title: true
hide_table_of_contents: true
sidebar_label: ipsw
description: Download and parse IPSW(s) from the internets
---
## ipsw download ipsw

Download and parse IPSW(s) from the internets

```
ipsw download ipsw [flags]
```

### Options

```
      --decrypt                 Attempt to decrypt the partial files if keys are available
      --dyld                    Extract dyld_shared_cache(s) from remote IPSW
  -a, --dyld-arch stringArray   dyld_shared_cache architecture(s) to remote extract
      --fcs-keys                Download AEA1 DMG fcs-key pem files
      --fcs-keys-json           Download AEA1 DMG fcs-keys as JSON
  -f, --flat                    Do NOT perserve directory structure when downloading with --pattern
  -h, --help                    help for ipsw
      --ibridge                 Download iBridge IPSWs
      --kernel                  Extract kernelcache from remote IPSW
      --latest                  Download latest IPSWs
      --macos                   Download macOS IPSWs
  -o, --output string           Folder to download files to
      --pattern string          Download remote files that match regex
      --show-latest-build       Show latest iOS build
      --show-latest-version     Show latest iOS version
  -u, --urls                    Dump URLs only
      --usb                     Download IPSWs for USB attached iDevices
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

