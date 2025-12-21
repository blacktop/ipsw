---
id: device-list
title: device-list
hide_title: true
hide_table_of_contents: true
sidebar_label: device-list
description: List all iOS devices
---
## ipsw device-list

List all iOS devices

### Synopsis

List all iOS devices from embedded device database.

NOTE: This database is sourced from Xcode's device_traits.db which includes
simulator devices and may not accurately map to physical hardware devices.
Some entries (e.g., iPad17,4-A, iPad17,4-B) represent simulator variants
rather than distinct hardware models.

```
ipsw device-list [flags]
```

### Options

```
  -h, --help    help for device-list
  -j, --json    Output as JSON
  -p, --plain   Output as non-interactive table
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

