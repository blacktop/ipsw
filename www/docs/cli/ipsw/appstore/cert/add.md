---
id: add
title: add
hide_title: true
hide_table_of_contents: true
sidebar_label: add
description: Create a new certificate using a certificate signing request
---
## ipsw appstore cert add

Create a new certificate using a certificate signing request

```
ipsw appstore cert add [flags]
```

### Options

```
  -c, --csr string      CSR content (https://developer.apple.com/help/account/create-certificates/create-a-certificate-signing-request)
  -h, --help            help for add
  -o, --output string   Folder to download profile to
  -t, --type string     Certificate type
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
  -i, --iss string      Issuer ID
  -j, --jwt string      JWT api key
  -k, --kid string      Key ID
      --no-color        disable colorize output
  -p, --p8 string       Path to App Store Connect API Key (.p8)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw appstore cert](/docs/cli/ipsw/appstore/cert)	 - Create, download, and revoke signing certificates for app development and distribution

