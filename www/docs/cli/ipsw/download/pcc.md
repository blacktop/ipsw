---
id: pcc
title: pcc
hide_title: true
hide_table_of_contents: true
sidebar_label: pcc
description: Download PCC VM files
---
## ipsw download pcc

Download PCC VM files

```
ipsw download pcc [INDEX] [flags]
```

### Examples

```bash
# Show available PCC releases info
❯ ipsw download pcc --info

# Show info for specific PCC release by index
❯ ipsw download pcc 42 --info

# Download specific PCC release by index
❯ ipsw download pcc 42

# Download PCC VM files interactively
❯ ipsw download pcc

# Download to specific directory
❯ ipsw download pcc --output ./pcc-vms

```

### Options

```
  -h, --help            help for pcc
  -i, --info            Show PCC Release info
      --insecure        do not verify ssl certs
  -o, --output string   Output directory to save files to
      --proxy string    HTTP/HTTPS proxy
      --restart-all     always restart resumable IPSWs
      --resume-all      always resume resumable IPSWs
      --skip-all        always skip resumable IPSWs
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

