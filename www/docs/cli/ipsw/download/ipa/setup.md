---
id: setup
title: setup
hide_title: true
hide_table_of_contents: true
sidebar_label: setup
description: Fetch the Apple files and prepare private online FairPlay state
---
## ipsw download ipa setup

Fetch the Apple files and prepare private online FairPlay state

### Synopsis

Fetch the Apple files and prepare private online FairPlay state.

Setup reuses the six Apple files in ~/.config/ipsw/fairplay/images if they pass
the integrity check. If the directory is missing or fails the check, setup
downloads about 300 MB from Apple. To use local files, pass --images DIR to
setup, signin and the download. This skips the image download. Creating the
prepared state still contacts Apple's provisioning service. A stop request waits for the file in
progress to finish. If setup reports publication uncertain, keep the directories
it names. Setup is not repeated automatically.

Before using the online route, unset APPSTORE_GUID, APPSTORE_PROXY, APPSTORE_REDOWNLOAD, APPSTORE_UA, IPSW_ANISETTE_URL.

```
ipsw download ipa setup [flags]
```

### Examples

```bash
# Check that this build supports the online route
❯ ipsw download ipa setup --check

# Fetch the Apple files and prepare the state
❯ ipsw download ipa setup

# Use local copies of the six Apple files
❯ ipsw download ipa setup --images /path/to/images

```

### Options

```
      --check[=true|false]   Check online IPA availability without preparing state
  -h, --help[=true|false]    help for setup
      --images string        Use the six Apple files in DIR instead of fetching them (absolute path without symbolic links)
  -o, --output string        Folder to download files to
      --username string      Username for authentication
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

* [ipsw download ipa](/docs/cli/ipsw/download/ipa)	 - Download App Packages from the iOS App Store

