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
  -a, --assistant         Only download the InstallAssistant.pkg
  -b, --build string      iOS BuildID (i.e. 16F203)
  -y, --confirm           do not prompt user for confirmation
  -h, --help              help for macos
      --insecure          do not verify ssl certs
      --latest            Download latest macOS installer
  -l, --list              Show latest macOS installers
      --proxy string      HTTP/HTTPS proxy
      --restart-all       always restart resumable IPSWs
      --resume-all        always resume resumable IPSWs
      --skip-all          always skip resumable IPSWs
  -v, --version string    iOS Version (i.e. 12.3.1)
  -w, --work-dir string   macOS installer creator working directory
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw download](/docs/cli/ipsw/download)	 - Download Apple Firmware files (and more)

