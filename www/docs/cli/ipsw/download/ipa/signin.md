---
id: signin
title: signin
hide_title: true
hide_table_of_contents: true
sidebar_label: signin
description: Sign in using the optional online FairPlay engine
---
## ipsw download ipa signin

Sign in using the optional online FairPlay engine

### Synopsis

Enter your Apple ID (visible) unless you supplied a username, then enter your password at the hidden prompt or pipe it with --password-stdin. If requested, enter your verification code at the hidden prompt.

If you paste your Apple ID and password together, the password line is discarded, so enter it again when the password prompt appears.

If the Apple ID or password prompt times out, this sign-in was not submitted. If the verification code prompt times out, no verification code was sent.

This version saves a version 2 session record. An older binary reports that record as corrupt. To replace it using the older binary, run ipsw download ipa signin --recover-session.

Before using the online route, unset APPSTORE_GUID, APPSTORE_PROXY, APPSTORE_REDOWNLOAD, APPSTORE_UA, IPSW_ANISETTE_URL.

```
ipsw download ipa signin [flags]
```

### Examples

```bash
# Sign in at the prompts
❯ ipsw download ipa signin

# Supply the Apple ID and pipe the password from the Keychain
❯ security find-generic-password -s appleid -w | ipsw download ipa signin --username user@example.com --password-stdin

# Replace a corrupt Keychain session
❯ ipsw download ipa signin --recover-session

```

### Options

```
  -h, --help[=true|false]              help for signin
      --images string                  Use the six Apple files in DIR instead of fetching them (absolute path without symbolic links)
  -o, --output string                  Folder to download files to
      --password-stdin[=true|false]    Read the online sign-in password from standard input
      --recover-session[=true|false]   Replace a corrupt Keychain session after successful online sign-in
      --username string                Username for authentication
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

