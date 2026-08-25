---
id: download
title: download
hide_title: true
hide_table_of_contents: true
sidebar_label: download
description: Download Apple Firmware files (and more)
---
## ipsw download

Download Apple Firmware files (and more)

### Synopsis

Download Apple firmware files, Developer Portal artifacts, App Store
packages, and other supported resources.

On an eligible direct CDN, --enable-node-selection spreads a multipart
download's range requests across the host's resolved addresses, measures
their throughput with real file bytes, and moves unfinished work away from
consistently slow addresses. It stays opt-in because some CDN routes are
faster without placement. Use --verbose to see whether placement activated
and which addresses were connected.

```
ipsw download [flags]
```

### Examples

```bash
# Opt into measured multi-address placement for an Apple CDN download
❯ ipsw download ipsw --device iPhone16,1 --latest --enable-node-selection
```

### Options

```
      --enable-node-selection   spread streams across CDN addresses by measured throughput
  -h, --help                    help for download
      --min-part-size int       minimum scheduler range size in MiB (0 uses the URL profile)
      --min-parts int           connections opened immediately and never retired (0 uses the URL profile)
      --parts int               maximum parallel connections per download (0 uses the URL profile)
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)
* [ipsw download appledb](/docs/cli/ipsw/download/appledb)	 - Download IPSWs from appledb
* [ipsw download dev](/docs/cli/ipsw/download/dev)	 - Download IPSWs (and more) from the Apple Developer Portal
* [ipsw download git](/docs/cli/ipsw/download/git)	 - Download github.com/orgs/apple-oss-distributions tarballs
* [ipsw download ipa](/docs/cli/ipsw/download/ipa)	 - Download App Packages from the iOS App Store
* [ipsw download ipsw](/docs/cli/ipsw/download/ipsw)	 - Download and parse IPSW(s) from ipsw.me
* [ipsw download kdk](/docs/cli/ipsw/download/kdk)	 - Download KDKs
* [ipsw download keys](/docs/cli/ipsw/download/keys)	 - Download FW keys from The iPhone Wiki
* [ipsw download macos](/docs/cli/ipsw/download/macos)	 - Download macOS installers
* [ipsw download ota](/docs/cli/ipsw/download/ota)	 - Download OTAs
* [ipsw download pcc](/docs/cli/ipsw/download/pcc)	 - Download PCC VM files
* [ipsw download rss](/docs/cli/ipsw/download/rss)	 - Read Releases - Apple Developer RSS Feed
* [ipsw download tss](/docs/cli/ipsw/download/tss)	 - Check signing status and download SHSH blobs
* [ipsw download wiki](/docs/cli/ipsw/download/wiki)	 - Download old(er) IPSWs from theiphonewiki.com

