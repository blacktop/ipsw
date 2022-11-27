---
description: How to configure ipsw with ~/.ipsw.yaml
---

# Configuration

> How to configure ipsw with ~/.ipsw.yaml

## `ipsw` config

You can also use a config file with `ipsw` so you don't have to use the flags

```bash
❯ cat ~/.ipsw.yml
```

```yaml
download:
  latest: true
  confirm: true
  white-list:
    - iPod9,1
    - iPhone14,2
  resume-all: true
  output: /SHARE/IPSWs
```

> This will download the `latest` IPSWs for _only_ the `iPod9,1` and the `iPhone14,2` without requesting user confirmation to download. It will also always try to `resume` previously interrupted downloads and will download everything to the `/SHARE/IPSWs` folder

You can also use environment variables to set `ipsw` config

```bash
❯ IPSW_DOWNLOAD_DEVICE=iPhone14,2 ipsw download ipsw --latest
```