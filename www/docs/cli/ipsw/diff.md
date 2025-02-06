---
id: diff
title: diff
hide_title: true
hide_table_of_contents: true
sidebar_label: diff
description: Diff IPSWs
---
## ipsw diff

Diff IPSWs

```
ipsw diff <IPSW> <IPSW> [flags]
```

### Examples

```bash
# Diff two IPSWs
❯ ipsw diff <old.ipsw> <new.ipsw> --fw --launchd --output <output/folder> --markdown
# Diff two IPSWs with KDKs
❯ ipsw diff <old.ipsw> <new.ipsw> --output <output/folder> --markdown 
	--kdk /Library/Developer/KDKs/KDK_15.0_24A5264n.kdk/System/Library/Kernels/kernel.release.t6031 
	--kdk /Library/Developer/KDKs/KDK_15.0_24A5279h.kdk/System/Library/Kernels/kernel.release.t6031
# Use a previously saved .idiff file
❯ ipsw diff --in <path/to/.idiff> --output <output/folder> --markdown
```

### Options

```
      --allow-list strings   Filter MachO sections to diff (e.g. __TEXT.__text)
      --block-list strings   Remove MachO sections to diff (e.g. __TEXT.__info_plist)
      --feat                 Diff feature flags
      --fw                   Diff other firmwares
  -h, --help                 help for diff
      --html                 Save diff as HTML file
  -i, --in string            Path to IPSW .idiff file
      --json                 Save diff as JSON file
  -k, --kdk stringArray      Path to KDKs to diff
      --launchd              Diff launchd configs
  -m, --markdown             Save diff as Markdown file
  -o, --output string        Folder to save diff output
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

