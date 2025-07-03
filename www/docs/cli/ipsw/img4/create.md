---
id: create
title: create
hide_title: true
hide_table_of_contents: true
sidebar_label: create
description: Create an IMG4 file
---
## ipsw img4 create

Create an IMG4 file

```
ipsw img4 create [flags]
```

### Examples

```bash
# Create IMG4 from existing IM4P with manifest and restore info
❯ ipsw img4 create --im4p payload.im4p --im4m manifest.im4m --im4r restore.im4r --output kernel.img4

# Create IMG4 from raw kernel with LZSS compression and manifest
❯ ipsw img4 create --input kernelcache --type krnl --description "Kernelcache" --compress lzss --im4m manifest.im4m --output kernel.img4

# Create IMG4 with boot nonce (generates IM4R automatically)
❯ ipsw img4 create --input sep-firmware.bin --type sepi --boot-nonce 1234567890abcdef --im4m manifest.im4m --output sep.img4

# Create IMG4 with extra data (extra data requires --compress lzss)
❯ ipsw img4 create --input payload.bin --type logo --compress lzss --extra extra.bin --im4m manifest.im4m --output logo.img4

# Create unsigned IMG4 (no manifest) - for testing only
❯ ipsw img4 create --input test.bin --type test --description "Test payload" --output test.img4

# Create IMG4 from iBoot with specific compression
❯ ipsw img4 create --input iboot.raw --type ibot --description "iBoot" --compress lzfse --im4m iboot.im4m --output iboot.img4

# Create IMG4 from raw data with common FourCC codes
❯ ipsw img4 create --input kernelcache.bin --type krnl --compress lzss --im4m manifest.im4m --output kernel.img4
❯ ipsw img4 create --input devicetree.bin --type dtre --compress lzss --im4m manifest.im4m --output devicetree.img4
❯ ipsw img4 create --input ramdisk.dmg --type rdsk --compress lzss --im4m manifest.im4m --output ramdisk.img4

# Re-type existing IM4P file with new type
❯ ipsw img4 create --im4p existing.im4p --type newt --im4m manifest.im4m --output retyped.img4
```

### Options

```
  -g, --boot-nonce string   Boot nonce to set in Img4 restore info
  -c, --compress string     IM4P compression to use (none, lzss, lzfse, lzfse_iboot) (default "none")
  -e, --extra string        Extra IM4P payload data to set
  -h, --help                help for create
  -m, --im4m string         Input Img4 manifest file
  -p, --im4p string         Input Img4 payload file
  -r, --im4r string         Input Img4 restore info file
  -i, --input string        Input file for IM4P payload data (raw data, not IM4P file)
  -o, --output string       Output file
  -t, --type string         IM4P type to set
  -v, --version string      IM4P version to set
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw img4](/docs/cli/ipsw/img4)	 - Parse and manipulate IMG4 files

