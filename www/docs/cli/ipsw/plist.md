---
id: plist
title: plist
hide_title: true
hide_table_of_contents: true
sidebar_label: plist
description: Dump plist as JSON
---
## ipsw plist

Dump plist as JSON

```
ipsw plist <file|watch-path> [flags]
```

### Options

```
  -e, --exclude strings   Exclude files/directories from watching (default [ContextStoreAgent.plist,com.apple.knowledge-agent.plist,com.apple.universalaccess.plist])
  -h, --help              help for plist
  -w, --watch             Watch file/Directory (default: $HOME/Library/Preferences)
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

