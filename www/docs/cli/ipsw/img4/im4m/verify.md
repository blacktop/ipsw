---
id: verify
title: verify
hide_title: true
hide_table_of_contents: true
sidebar_label: verify
description: 🚧 Verify IM4M manifest against build manifest
---
## ipsw img4 im4m verify

🚧 Verify IM4M manifest against build manifest

```
ipsw img4 im4m verify <IM4M> [flags]
```

### Examples

```bash
# Verify IM4M against build manifest
❯ ipsw img4 im4m verify --build-manifest BuildManifest.plist manifest.im4m

# Allow extra properties in IM4M
❯ ipsw img4 im4m verify --build-manifest BuildManifest.plist --allow-extra manifest.im4m
```

### Options

```
      --allow-extra             Allow IM4M to have properties not in build manifest
  -b, --build-manifest string   Build manifest file for verification
  -h, --help                    help for verify
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw img4 im4m](/docs/cli/ipsw/img4/im4m)	 - IM4M manifest operations

