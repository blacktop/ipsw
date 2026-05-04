---
id: diff
title: diff
hide_title: true
hide_table_of_contents: true
sidebar_label: diff
description: Diff IPSWs, OTAs, or patched OTA DMG directories
---
## ipsw diff

Diff IPSWs, OTAs, or patched OTA DMG directories

```
ipsw diff <IPSW|OTA|DIR> <IPSW|OTA|DIR> [flags]
```

### Examples

```bash
# Diff two IPSWs
❯ ipsw diff <old.ipsw> <new.ipsw> --fw --launchd --output <output/folder> --markdown
# Diff two OTAs (darwin only, requires full OTAs)
❯ ipsw diff <old.ota> <new.ota> --output <output/folder> --markdown
# Diff two OTAs with AEA key database
❯ ipsw diff <old.ota> <new.ota> --key-db keys.json --output <output/folder> --markdown
# Diff two ota patch rsr output directories
❯ ipsw diff <old_rsr_dir> <new_rsr_dir> --files --output <output/folder> --markdown
# Diff two IPSWs with KDKs
❯ ipsw diff <old.ipsw> <new.ipsw> --output <output/folder> --markdown
	--kdk /Library/Developer/KDKs/KDK_15.0_24A5264n.kdk/System/Library/Kernels/kernel.release.t6031
	--kdk /Library/Developer/KDKs/KDK_15.0_24A5279h.kdk/System/Library/Kernels/kernel.release.t6031
```

### Options

```
      --allow-list strings   Filter MachO sections to diff (e.g. __TEXT.__text)
      --block-list strings   Remove MachO sections to diff (e.g. __TEXT.__info_plist)
      --ent                  Diff MachO entitlements
      --feat                 Diff feature flags
      --files                Diff files
      --fw                   Diff other firmwares
  -h, --help                 help for diff
      --html                 Output diff as HTML
      --insecure             Allow insecure connections when fetching AEA keys
      --json                 Output diff as JSON
  -k, --kdk stringArray      Path to KDKs to diff
      --key-db string        Path to AEA keys JSON database (for OTA diffs)
      --key-val string       Base64 encoded AEA symmetric encryption key (for OTA diffs)
      --launchd              Diff launchd configs
      --low-memory           Use disk caching to reduce RAM usage
  -m, --markdown             Output diff as Markdown
  -o, --output string        Folder to save diff output
      --sandbox              Diff compiled sandbox profiles
  -s, --signatures string    Path to symbolicator signatures folder
      --starts               Diff MachO function starts
      --strs                 Diff MachO cstrings
  -t, --title string         Title of the diff
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

