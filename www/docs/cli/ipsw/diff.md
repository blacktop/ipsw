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

### Synopsis

Diff IPSWs, OTAs, or patched OTA DMG directories

When a section fails, the other sections are still reported and the command
exits nonzero after writing the report. The report names the failed sections
and any sections skipped because they do not apply to the inputs.

With --markdown and --output, status.json beside README.md records the same:
{"complete": false, "failed_sections": ["..."], "skipped_sections": [{"section": "...", "reason": "..."}]}
A nonzero exit with "complete": true means only cleanup failed.

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
      --allow-list strings                     Filter MachO sections to diff (e.g. __TEXT.__text)
      --block-list strings                     Remove MachO sections to diff (e.g. __TEXT.__info_plist)
      --cache-dir string                       Override default cache directory (default: $XDG_CACHE_HOME/ipsw/diffs or ~/Library/Caches/ipsw/diffs)
      --cache-max-size string                  LRU eviction threshold for the cache directory (e.g. 5GiB, 500MB) (default "5GiB")
      --clean[=true|false]                     Delete the cached DB for this IPSW pair before running
      --device string                          IPSW device product type or board to compare
      --ent[=true|false]                       Diff MachO entitlements
      --feat[=true|false]                      Diff feature flags
      --files[=true|false]                     Diff files
      --fw[=true|false]                        Diff other firmwares
  -h, --help[=true|false]                      help for diff
      --html[=true|false]                      Output diff as HTML
      --ignore-build-timestamps[=true|false]   Ignore compiler build timestamp CStrings
      --insecure[=true|false]                  Allow insecure connections when fetching AEA keys
      --json[=true|false]                      Output diff as JSON
  -k, --kdk stringArray                        Path to KDKs to diff
      --key-db string                          Path to AEA keys JSON database (for OTA diffs)
      --key-val string                         Base64 encoded AEA symmetric encryption key (for OTA diffs)
      --launchd[=true|false]                   Diff launchd configs
      --loc[=true|false]                       Diff localized string resources (.strings, .stringsdict, .loctable)
  -m, --markdown[=true|false]                  Output diff as Markdown
      --no-cache[=true|false]                  Disable persistent cache; use a temp SQLite DB cleaned on exit
  -o, --output string                          Folder to save diff output
      --sandbox[=true|false]                   Diff compiled sandbox profiles (alone, runs kernelcache-only)
  -s, --signatures string                      Path to symbolicator signatures folder
      --starts[=true|false]                    Diff MachO function starts
      --strs[=true|false]                      Diff MachO cstrings
  -t, --title string                           Title of the diff
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

