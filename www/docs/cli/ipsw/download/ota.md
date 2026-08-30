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

### Synopsis

Download OTA updates resolved live from Apple's Pallas
(gdmf.apple.com/v2/assets) and asset-set (gdmf.apple.com/v2/pmv) services.

With --json, output is always an indented, schema-versioned envelope. Schema
version 1 contains an otas array, which is empty when no OTA matches. Entries
are unique per URL and sorted by os, newest version, newest build, delivery,
prerequisite build, then URL.
Each entry carries os, version, version_extra (RSR suffix), build, channel,
posting_date, delivery (full, delta, or rsr), prerequisite, supported_devices,
supported_models, url, download_size, unarchived_size, sha1, sha256,
encryption, and provenance. Anything Apple did not supply is null; sha256,
posting_date, and RC status are never inferred. channel.kind is release,
beta, rc, or unknown. Every sighting and the asset's own markers are
classified from Apple markers only (rc when the documentation ID ends in
RC, beta when Apple's ReleaseType is Beta or the documentation ID contains
Beta, release when a release audience or the public mesu feed served the
asset with no seed marker) and the kind is emitted only when all decided
evidence agrees; conflicting or undecided evidence yields unknown.
channel.audiences and provenance.sightings list every Pallas audience and
asset set that advertised the URL, each with its own nullable is_seed.
provenance.asset_sets lists matching gdmf pmv entries. posting_date is set
only when dates from Pallas and PublicAssetSets agree.
Decryption keys are never included; use --fcs-keys for those.


```
ipsw download ota [options] [flags]
```

### Examples

```bash
# Download the iOS 14.8.1 OTA for the iPhone10,1
❯ ipsw download ota --platform ios --version 14.8.1 --device iPhone10,1

# Get all the latest BETA iOS OTAs as JSON
❯ ipsw download ota --platform ios --beta --json

# Get the macOS 26.7 RC OTA URLs for the Mac17,6
❯ ipsw download ota --platform macos --version 26.7 --device Mac17,6 --rc --urls

# Download latest tvOS OTA and extract kernelcache
❯ ipsw download ota --platform tvos --latest --kernel

# Download Xcode Simulator Runtime OTAs
❯ ipsw download ota --platform ios --sim --build "22F77"

# Get AEA decryption keys as JSON from latest iOS OTAs
❯ ipsw download ota --platform ios --latest --fcs-keys

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
      --fcs-keys                 Get AEA decryption keys as JSON database from OTA metadata
  -f, --flat                     Do NOT preserve directory structure when downloading with --pattern
  -h, --help                     help for ota
      --info                     Show all the latest OTAs available
      --insecure                 do not verify ssl certs
  -j, --json                     Dump a versioned OTA envelope as JSON (never includes decryption keys)
  -k, --kernel                   Extract kernelcache from remote OTA zip
      --latest                   Download latest OTAs
  -m, --model string             iOS Model (i.e. D321AP)
  -o, --output string            Folder to download files to
      --pattern string           Download remote files that match regex
      --platform string          Platform to download (ios, watchos, tvos, audioos || accessory, macos, recovery)
      --proxy string             HTTP/HTTPS proxy
      --rc                       Download confirmed RC OTAs (queried from the beta seed audiences)
  -_, --remove-commas            replace commas in IPSW filename with underscores
      --restart-all              always restart resumable IPSWs
      --rsr                      Download Rapid Security Response OTAs
      --show-latest-build        Show latest iOS build
      --show-latest-version      Show latest iOS version
      --sim                      Download Simulator OTAs
      --skip-all                 continue past files locked by another download process
  -u, --urls                     Dump URLs only
  -v, --version string           iOS Version (i.e. 12.3.1)
      --white-list stringArray   iOS device white list
```

### Options inherited from parent commands

```
      --color                   colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --enable-node-selection   spread streams across CDN addresses by measured throughput
      --min-part-size int       minimum scheduler range size in MiB (0 uses the URL profile)
      --min-parts int           connections opened immediately and never retired (0 uses the URL profile)
      --no-color                disable colorize output
      --parts int               maximum parallel connections per download (0 uses the URL profile)
  -V, --verbose                 verbose output
```

### SEE ALSO

* [ipsw download](/docs/cli/ipsw/download)	 - Download Apple Firmware files (and more)

