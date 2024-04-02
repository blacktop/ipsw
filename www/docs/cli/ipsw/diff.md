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

### Options

```
  -f, --filter strings    Filter MachO sections to diff (e.g. __TEXT.__text)
      --fw                Diff other firmwares
  -h, --help              help for diff
      --html              Save diff as HTML file
      --json              Save diff as JSON file
  -k, --kdk stringArray   Path to KDKs to diff
      --launchd           Diff launchd configs
  -o, --output string     Folder to save diff output
  -t, --title string      Title of the diff
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

