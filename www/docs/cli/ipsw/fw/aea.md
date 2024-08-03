---
id: aea
title: aea
hide_title: true
hide_table_of_contents: true
sidebar_label: aea
description: Parse AEA1 DMGs
---
## ipsw fw aea

Parse AEA1 DMGs

```
ipsw fw aea [flags]
```

### Options

```
  -e, --encrypt          AEA encrypt file
  -f, --fcs-key          Get fcs-key JSON
  -h, --help             help for aea
      --id               Print AEA file ID
  -i, --info             Print info
  -k, --key              Get archive decryption key
  -b, --key-val string   Base64 encoded symmetric encryption key
  -o, --output string    Folder to extract files to
  -p, --pem string       AEA private_key.pem file
      --pem-db string    AEA pem DB JSON file
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw fw](/docs/cli/ipsw/fw)	 - Firmware commands

