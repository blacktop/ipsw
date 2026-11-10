---
id: export-auth
title: export-auth
hide_title: true
hide_table_of_contents: true
sidebar_label: export-auth
description: Export existing local authorization for offline IPA decryption
---
## ipsw macho export-auth

Export existing local authorization for offline IPA decryption

### Synopsis

Export existing local authorization on macOS. Run as your normal user; a short-lived helper requests sudo approval for the protected read. The authorization is saved to ~/.config/ipsw/fairplay/authorization.fpauth unless --output names another private directory. No account login or download is performed.

```
ipsw macho export-auth [flags]
```

### Examples

```bash
# Export to ~/.config/ipsw/fairplay/authorization.fpauth as your normal macOS user;
# the helper requests sudo approval
❯ ipsw macho export-auth

# Export to ./private-auth/authorization.fpauth instead
❯ ipsw macho export-auth --output ./private-auth
```

### Options

```
  -h, --help[=true|false]   help for export-auth
  -o, --output string       Private output directory for authorization.fpauth (default ~/.config/ipsw/fairplay)
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

