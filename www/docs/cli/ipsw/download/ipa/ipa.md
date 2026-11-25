---
id: ipa
title: ipa
hide_title: true
hide_table_of_contents: true
sidebar_label: ipa
description: Download App Packages from the iOS App Store
---
## ipsw download ipa

Download App Packages from the iOS App Store

### Synopsis

Download an app from the App Store by bundle ID. Free apps only.

The first download fetches Apple's support files (about 300 MB) and asks you to sign in.

--password, --proxy, --insecure, --sms, --store-front and --vault-password select the legacy downloader, which has its own sign-in.

```
ipsw download ipa [flags]
```

### Examples

```bash
# Download an app by bundle ID (the first run sets up and signs in)
❯ ipsw download ipa com.zhiliaoapp.musically

# Search for apps and pick which to download
❯ ipsw download ipa --search twitter

# Get the free license for an app the account does not own yet
❯ ipsw download ipa --purchase com.zhiliaoapp.musically

# Download and decrypt into ./apps (needs 'ipsw macho export-auth' once)
❯ ipsw download ipa --decrypt --output ./apps com.zhiliaoapp.musically
```

### Options

```
      --decrypt[=true|false]          Also decrypt the IPA (needs 'ipsw macho export-auth' once)
      --force[=true|false]            Overwrite an IPA that already exists
  -h, --help[=true|false]             help for ipa
      --insecure[=true|false]         do not verify ssl certs (legacy downloader)
  -o, --output string                 Folder to download files to
      --password string               Password for authentication (legacy downloader)
      --password-stdin[=true|false]   Read the Apple ID password from standard input
      --proxy string                  HTTP/HTTPS proxy (legacy downloader)
      --purchase[=true|false]         Get the free license if the account does not own the app
      --search[=true|false]           Search for app to download
      --sms[=true|false]              Prefer SMS Two-factor authentication (legacy downloader)
  -s, --store-front string            The country code for the App Store to download from (legacy downloader) (default "US")
      --username string               Username for authentication
  -k, --vault-password string         Password to unlock credential vault (only for file vaults) (legacy downloader)
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
* [ipsw download ipa setup](/docs/cli/ipsw/download/ipa/setup)	 - Prepare this Mac for IPA downloads
* [ipsw download ipa signin](/docs/cli/ipsw/download/ipa/signin)	 - Sign in to the App Store for IPA downloads

