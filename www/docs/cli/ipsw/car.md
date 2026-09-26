---
id: car
title: car
hide_title: true
hide_table_of_contents: true
sidebar_label: car
description: Inspect and extract compiled asset catalogs
---
## ipsw car

Inspect and extract compiled asset catalogs

### Synopsis

Inspect a compiled asset catalog and optionally extract its renditions.
Use --metadata-only --json to inspect keys before selecting exact numeric
variants. Name globs match stored rendition names and logical asset names;
requested numeric keys must exist and match exactly, including zero.
--json cannot be combined with --dry-run or --manifest -.

HEIF/PDF/SVG rendering and native BC7 decoding require macOS with cgo.
ASTC decoding can also use an external astcenc executable through
--astc-decoder. Original JPEG and WebP payloads are preserved unchanged.

Exports replace existing rendition files atomically. Unsupported layouts
and codecs are reported separately; decode or write failures cause a nonzero
exit. Use --raw to preserve unsupported renditions as original CSI records.


```
ipsw car <Assets.car> [flags]
```

### Examples

```bash
# Inspect metadata without decoding images
$ ipsw car Assets.car --metadata-only --json

# Extract all supported renditions
$ ipsw car Assets.car --output assets

# Extract matching variants; quote globs to prevent shell expansion
$ ipsw car Assets.car --name 'AppIcon*' --scale 2 --idiom 1 --output icons

# Preview exact keys, crops, and destinations without extracting
$ ipsw car Assets.car --dry-run --output assets

# Render embedded documents/images and record every export result
$ ipsw car Assets.car --render --apply-orientation --output images --manifest exports.json

# Preserve original CSI data, including unsupported encodings
$ ipsw car Assets.car --raw --output original

```

### Options

```
      --appearance string          Match the exact numeric appearance key
      --apply-orientation          Apply EXIF rotation or mirroring to PNG exports
      --astc-decoder string        Path to astcenc for ASTC decoding
      --block-profile string       Write block profile to file
      --cpu-profile string         Write CPU profile to file
      --dry-run                    Preview export destinations without decoding or extracting assets
      --gamut string               Match the exact numeric display-gamut key
      --goroutine-profile string   Write goroutine profile to file
  -h, --help                       help for car
      --idiom string               Match the exact idiom key (0=universal, 1=phone, 2=pad, 3=desktop)
  -j, --json                       Output the selected inventory as JSON
      --localization string        Match the exact numeric localization key
      --manifest string            Write an export manifest to a new file, or '-' for stdout
      --mem-profile string         Write memory profile to file
      --mem-profile-rate int       Memory profiling rate (0 to disable)
      --metadata-only              Inspect catalog metadata without decoding pixels
      --mutex-profile string       Write mutex profile to file
      --name stringArray           Match a logical or rendition name glob (repeatable)
  -o, --output string              Output folder to extract renditions
      --raw                        Export complete encoded CSI renditions instead of converted assets
      --render                     Render HEIF, PDF, and SVG payloads as PNG
      --scale string               Match the exact scale key (1, 2, 3)
      --trace string               Write execution trace to file
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)
