---
id: signin
title: signin
hide_title: true
hide_table_of_contents: true
sidebar_label: signin
description: Sign in to the App Store for IPA downloads
---
## ipsw download ipa signin

Sign in to the App Store for IPA downloads

### Synopsis

Sign in with your Apple ID and save the session in the Keychain.

ipsw asks for the Apple ID, the password and a verification code if Apple requests one.

```
ipsw download ipa signin [flags]
```

### Examples

```bash
# Sign in at the prompts
❯ ipsw download ipa signin

# Sign in from a script, reading the password from the Keychain
❯ security find-generic-password -s appleid -w | ipsw download ipa signin --username user@example.com --password-stdin
```

### Options

```
  -h, --help[=true|false]             help for signin
      --password-stdin[=true|false]   Read the Apple ID password from standard input
      --username string               Apple ID to sign in with
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

