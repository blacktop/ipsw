---
id: extract
title: extract
hide_title: true
hide_table_of_contents: true
sidebar_label: extract
description: Extract IM4P data
---
## ipsw img4 im4p extract

Extract IM4P data

### Synopsis

Extract IM4P payload data or extra metadata.

```
ipsw img4 im4p extract <IM4P> [flags]
```

### Examples

```bash
# Extract decompressed payload data
❯ ipsw img4 im4p extract kernelcache.im4p

# Extract extra data (if present)
❯ ipsw img4 im4p extract --extra kernelcache.im4p

# Extract keybags as JSON
❯ ipsw img4 im4p extract --kbag encrypted.im4p

# Decrypt and extract payload
❯ ipsw img4 im4p extract --iv 1234... --key 5678... encrypted.im4p

# Auto-lookup key and decrypt
❯ ipsw img4 im4p extract --lookup --lookup-device iPhone14,2 --lookup-build 20H71 RestoreRamDisk.im4p

# Auto-detect device/build from folder structure (e.g., 22F76__iPhone11,8/...)
❯ ipsw img4 im4p extract --lookup /path/to/22F76__iPhone11,8/sep-firmware.n841.RELEASE.im4p

# Extract to specific output file
❯ ipsw img4 im4p extract --output kernel.bin kernelcache.im4p
```

### Options

```
  -e, --extra                  Extract extra data
  -h, --help                   help for extract
  -i, --iv string              AES iv for decryption
      --iv-key string          AES iv+key for decryption
  -b, --kbag                   Extract keybags as JSON
  -k, --key string             AES key for decryption
      --lookup                 Auto-lookup IV/key on theapplewiki.com
      --lookup-build string    Build number for key lookup (e.g., 20H71)
      --lookup-device string   Device identifier for key lookup (e.g., iPhone14,2)
  -o, --output string          Output file path
  -r, --raw                    Extract raw data (compressed/encrypted)
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw img4 im4p](/docs/cli/ipsw/img4/im4p)	 - IM4P payload operations

