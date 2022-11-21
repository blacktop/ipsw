---
date: 2022-11-20T23:11:40-07:00
title: "ipsw download ota"
slug: ipsw_download_ota
url: /commands/ipsw_download_ota/
---
## ipsw download ota

Download OTAs

```
ipsw download ota [options] [flags]
```

### Options

```
      --beta                    Download Beta OTAs
      --driver-kit              Extract DriverKit dyld_shared_cache(s) from remote OTA zip
      --dyld                    Extract dyld_shared_cache(s) from remote OTA zip
  -a, --dyld-arch stringArray   dyld_shared_cache architecture(s) to remote extract
  -f, --flat                    Do NOT perserve directory structure when downloading with --pattern
  -h, --help                    help for ota
      --info                    Show all the latest OTAs available
      --info-type string        OS type to show OTAs for
  -j, --json                    Dump URLs as JSON only
  -k, --kernel                  Extract kernelcache from remote OTA zip
  -o, --output string           Folder to download files to
      --pattern string          Download remote files that match regex
  -p, --platform string         Platform to download (ios, watchos, tvos, audioos || accessory, macos, recovery)
      --rsr                     Download Rapid Security Response OTAs
  -u, --urls                    Dump URLs only
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

* [ipsw download](/cmd/ipsw_download/)	 - Download Apple Firmware files (and more)

