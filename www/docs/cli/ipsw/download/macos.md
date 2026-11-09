---
id: macos
title: macos
hide_title: true
hide_table_of_contents: true
sidebar_label: macos
description: Download macOS installers
---
## ipsw download macos

Download macOS installers

```
ipsw download macos [flags]
```

### Examples

```bash
# List available macOS installers
❯ ipsw download macos --list

# Download latest macOS installer
❯ ipsw download macos --latest

# Download specific macOS version
❯ ipsw download macos --version 14.0

# Download only InstallAssistant.pkg
❯ ipsw download macos --version 14.0 --assistant

```

### Options

```
  -a, --assistant[=true|false]     Only download the InstallAssistant.pkg
  -b, --build string               iOS BuildID (i.e. 16F203)
  -y, --confirm[=true|false]       do not prompt user for confirmation
  -h, --help[=true|false]          help for macos
      --insecure[=true|false]      do not verify ssl certs
      --latest[=true|false]        Download latest macOS installer
  -l, --list[=true|false]          Show latest macOS installers
      --proxy string               HTTP/HTTPS proxy
      --restart-all[=true|false]   always restart resumable IPSWs
      --skip-all[=true|false]      continue past files locked by another download process
  -v, --version string             iOS Version (i.e. 12.3.1)
  -w, --work-dir string            macOS installer creator working directory
```

### Options inherited from parent commands

```
      --color[=true|false]                   colorize output
      --config string                        config file (default is $HOME/.config/ipsw/config.yaml)
      --enable-node-selection[=true|false]   spread streams across CDN addresses by measured throughput
      --min-part-size int                    minimum scheduler range size in MiB (0 uses the URL profile)
      --min-parts int                        connections opened immediately and never retired (0 uses the URL profile)
      --no-color[=true|false]                disable colorize output
      --parts int                            maximum parallel connections per download (0 uses the URL profile)
  -V, --verbose[=true|false]                 verbose output
```

### SEE ALSO

* [ipsw download](/docs/cli/ipsw/download)	 - Download Apple Firmware files (and more)

