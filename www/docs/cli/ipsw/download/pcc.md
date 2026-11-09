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

### Synopsis

Download PCC release assets. Set CLOUDSDK_AUTH_ACCESS_TOKEN to authorize downloads from Google Cloud Storage.

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

# Filter by cloudOS build prefix and pick interactively
❯ ipsw download pcc --build 5E --app TIE

# Filter by OS BuildManifest ProductBuildVersion prefix
❯ ipsw download pcc --os-build 23E5207q --info

# Show only releases whose OS IPSW contains vphone600 firmware
❯ ipsw download pcc --vphone --info

# Show compact release summaries and labeled asset URLs
❯ ipsw download pcc --info --urls

# Show only the newest vphone release as a compact summary
❯ ipsw download pcc --vphone --latest

# Download PCC VM files interactively
❯ ipsw download pcc

# Download to specific directory
❯ ipsw download pcc --output ./pcc-vms

```

### Options

```
      --app string                 Filter by cloudOS application name (e.g. TIE, 'TIE Proxy')
      --build string               Filter by cloudOS build version prefix (e.g. 5E, 5E290)
  -h, --help[=true|false]          help for pcc
  -i, --info[=true|false]          Show PCC Release info
      --insecure[=true|false]      do not verify ssl certs
      --latest[=true|false]        Show only the newest PCC release after filtering
      --os-build string            Filter by OS ProductBuildVersion prefix (e.g. 23E5207q); resolved via partial-zip, cached
  -o, --output string              Output directory to save files to
      --proxy string               HTTP/HTTPS proxy
      --restart-all[=true|false]   always restart resumable IPSWs
      --skip-all[=true|false]      continue past files locked by another download process
      --train string               Filter by cloudOS build train substring (e.g. LuckE)
  -u, --urls[=true|false]          Show compact release summaries and asset URLs without saving assets
      --version string             Filter by OS ProductVersion prefix (e.g. 26.3); resolved via partial-zip, cached
      --vphone[=true|false]        Filter to OS IPSWs containing vphone600 firmware; resolved via partial-zip, cached
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

