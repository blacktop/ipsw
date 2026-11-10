---
id: decrypt-ipa
title: decrypt-ipa
hide_title: true
hide_table_of_contents: true
sidebar_label: decrypt-ipa
description: Decrypt an IPA using an exported local authorization file
---
## ipsw macho decrypt-ipa

Decrypt an IPA using an exported local authorization file

### Synopsis

Decrypt a licensed IPA into a new output directory. The authorization exported by 'ipsw macho export-auth' is read from ~/.config/ipsw/fairplay/authorization.fpauth unless --auth names another file.

```
ipsw macho decrypt-ipa <IPA> [flags]
```

### Examples

```bash
# Decrypt a licensed IPA using ~/.config/ipsw/fairplay/authorization.fpauth
❯ ipsw macho decrypt-ipa ./LicensedApp.ipa --output ./decrypted-app

# Decrypt using an authorization file from another location
❯ ipsw macho decrypt-ipa ./LicensedApp.ipa --auth ./authorization.fpauth --output ./decrypted-app
```

### Options

```
      --auth string         Exported local authorization file (default ~/.config/ipsw/fairplay/authorization.fpauth)
  -h, --help[=true|false]   help for decrypt-ipa
  -o, --output string       New output directory (must not exist)
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw macho](/docs/cli/ipsw/macho)	 - Parse MachO

