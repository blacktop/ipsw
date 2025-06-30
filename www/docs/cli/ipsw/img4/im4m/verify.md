---
id: verify
title: verify
hide_title: true
hide_table_of_contents: true
sidebar_label: verify
description: Verify IM4M manifest against build manifest
---
## ipsw img4 im4m verify

Verify IM4M manifest against build manifest

```
ipsw img4 im4m verify <IM4M> [flags]
```

### Examples

```bash
# Verify IM4M against build manifest (standard mode)
❯ ipsw img4 im4m verify --build-manifest BuildManifest.plist manifest.im4m

# Strict verification (requires all BuildManifest components)
❯ ipsw img4 im4m verify --build-manifest BuildManifest.plist --strict manifest.im4m
```

### Options

```
  -b, --build-manifest string   Build manifest file for verification
  -h, --help                    help for verify
  -s, --strict                  Strict mode: fail if any BuildManifest components are missing from IM4M
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

