---
id: sign
title: sign
hide_title: true
hide_table_of_contents: true
sidebar_label: sign
description: Codesign a MachO
---
## ipsw macho sign

Codesign a MachO

```
ipsw macho sign <MACHO> [flags]
```

### Examples

```bash
  # Ad-hoc codesign a MachO w/ entitlements
  ❯ ipsw macho sign --id com.apple.ls --ad-hoc --ent entitlements.plist <MACHO>
```

### Options

```
  -a, --ad-hoc[=true|false]      ad-hoc codesign
  -c, --cert string              p12 codesign with cert
  -e, --ent string               entitlements.plist file
  -d, --ent-der string           entitlements asn1/der file
  -h, --help[=true|false]        help for sign
  -i, --id string                sign with identifier
      --insecure[=true|false]    do not verify ssl certs
  -o, --output string            Output codesigned file
  -f, --overwrite[=true|false]   Overwrite file
      --proxy string             HTTP/HTTPS proxy
  -p, --pw string                p12 cert password
  -t, --team string              sign with team id
      --timeserver string        timeserver URL (default "http://timestamp.apple.com/ts01")
      --ts[=true|false]          timestamp signature
      --verify[=true|false]      Verify codesignature after signing via codesign --verify (darwin only)
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

