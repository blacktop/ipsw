---
date: 2022-11-20T23:11:40-07:00
title: "ipsw download"
slug: ipsw_download
url: /commands/ipsw_download/
---
## ipsw download

Download Apple Firmware files (and more)

```
ipsw download [flags]
```

### Options

```
      --black-list stringArray   iOS device black list
  -b, --build string             iOS BuildID (i.e. 16F203)
  -y, --confirm                  do not prompt user for confirmation
  -d, --device string            iOS Device (i.e. iPhone11,2)
  -h, --help                     help for download
      --insecure                 do not verify ssl certs
  -m, --model string             iOS Model (i.e. D321AP)
      --proxy string             HTTP/HTTPS proxy
  -_, --remove-commas            replace commas in IPSW filename with underscores
      --restart-all              always restart resumable IPSWs
      --resume-all               always resume resumable IPSWs
      --skip-all                 always skip resumable IPSWs
  -v, --version string           iOS Version (i.e. 12.3.1)
      --white-list stringArray   iOS device white list
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/cmd/ipsw/)	 - Download and Parse IPSWs (and SO much more)
* [ipsw download dev](/cmd/ipsw_download_dev/)	 - Download IPSWs (and more) from https://developer.apple.com/download
* [ipsw download git](/cmd/ipsw_download_git/)	 - Download github.com/orgs/apple-oss-distributions tarballs
* [ipsw download ipsw](/cmd/ipsw_download_ipsw/)	 - Download and parse IPSW(s) from the internets
* [ipsw download macos](/cmd/ipsw_download_macos/)	 - Download macOS installers
* [ipsw download ota](/cmd/ipsw_download_ota/)	 - Download OTAs
* [ipsw download rss](/cmd/ipsw_download_rss/)	 - Read Releases - Apple Developer RSS Feed
* [ipsw download tss](/cmd/ipsw_download_tss/)	 - 🚧 Download SHSH Blobs
* [ipsw download wiki](/cmd/ipsw_download_wiki/)	 - Download old(er) IPSWs from theiphonewiki.com

