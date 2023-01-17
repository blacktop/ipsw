---
id: sign
title: sign
hide_title: true
hide_table_of_contents: true
sidebar_label: sign
description: Codesign a MachO
last_update:
  date: 2023-01-16T23:18:46-07:00
  author: blacktop
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
  -a, --ad-hoc              ad-hoc codesign
  -c, --cert string         p12 codesign with cert
  -e, --ent string          entitlements.plist file
  -d, --ent-der string      entitlements asn1/der file
  -h, --help                help for sign
  -i, --id string           sign with identifier
      --insecure            do not verify ssl certs
  -o, --output string       Output codesigned file
  -f, --overwrite           Overwrite file
      --proxy string        HTTP/HTTPS proxy
  -p, --pw string           p12 cert password
      --timeserver string   timeserver URL (default "http://timestamp.apple.com/ts01")
  -t, --ts                  timestamp signature
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw macho](/docs/cli/ipsw/macho)	 - Parse MachO

