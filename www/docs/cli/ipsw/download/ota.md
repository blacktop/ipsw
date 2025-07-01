---
id: ota
title: ota
hide_title: true
hide_table_of_contents: true
sidebar_label: ota
description: Download OTAs
---
## ipsw download ota

Download OTAs

```
ipsw download ota [options] [flags]
```

### Examples

```bash
# Download the iOS 14.8.1 OTA for the iPhone10,1
❯ ipsw download ota --platform ios --version 14.8.1 --device iPhone10,1

# Get all the latest BETA iOS OTAs URLs as JSON
❯ ipsw download ota --platform ios --beta --urls --json

# Download latest tvOS OTA and extract kernelcache
❯ ipsw download ota --platform tvos --latest --kernel

# Download Xcode Simulator Runtime OTAs
❯ ipsw download ota --platform ios --sim --build "22F77"

```

### Options

```
      --beta                     Download Beta OTAs
      --black-list stringArray   iOS device black list
  -b, --build string             iOS BuildID (i.e. 16F203)
  -y, --confirm                  do not prompt user for confirmation
      --delta                    Download Delta OTAs
  -d, --device string            iOS Device (i.e. iPhone11,2)
      --driver-kit               Extract DriverKit dyld_shared_cache(s) from remote OTA zip
      --dyld                     Extract dyld_shared_cache(s) from remote OTA zip
  -a, --dyld-arch stringArray    dyld_shared_cache architecture(s) to remote extract
  -f, --flat                     Do NOT perserve directory structure when downloading with --pattern
  -h, --help                     help for ota
      --info                     Show all the latest OTAs available
      --insecure                 do not verify ssl certs
  -j, --json                     Dump URLs as JSON only
  -k, --kernel                   Extract kernelcache from remote OTA zip
      --latest                   Download latest OTAs
  -m, --model string             iOS Model (i.e. D321AP)
  -o, --output string            Folder to download files to
      --pattern string           Download remote files that match regex
      --platform string          Platform to download (ios, watchos, tvos, audioos || accessory, macos, recovery)
      --proxy string             HTTP/HTTPS proxy
  -_, --remove-commas            replace commas in IPSW filename with underscores
      --restart-all              always restart resumable IPSWs
      --resume-all               always resume resumable IPSWs
      --rsr                      Download Rapid Security Response OTAs
      --show-latest-build        Show latest iOS build
      --show-latest-version      Show latest iOS version
      --sim                      Download Simulator OTAs
      --skip-all                 always skip resumable IPSWs
  -u, --urls                     Dump URLs only
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

