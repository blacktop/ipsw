---
description: How to configure ipsw with `config.yml`
---

# Configuration

> How to configure ipsw with `config.yml`

## `ipsw` config.yml

You can also use a config file with `ipsw`/`ipswd` so you don't have to use the flags

```mdx-code-block
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';
```

```mdx-code-block
<Tabs>
<TabItem value="macOS">
```

```bash
❯ cat ~/.config/ipsw/config.yml
```

```mdx-code-block
</TabItem>
<TabItem value="Linux">
```

```bash
❯ cat /etc/ipsw/config.yml
```

Installed with `snap`

```bash
❯ cat /root/snap/ipswd/common/ipsw/config.yml
```

```mdx-code-block
</TabItem>
<TabItem value="Windows">
```

```bash
PS> cat $AppData/ipsw/config.yml
```

```mdx-code-block
</TabItem>
</Tabs>
```

```yaml
download:
  latest: true
  confirm: true
  white-list:
    - iPod9,1
    - iPhone14,2
  resume-all: true
  ipsw:
    output: /SHARE/IPSWs # this is the --output for the `ipsw download ipsw` command
```

> This will download the `latest` IPSWs for _only_ the `iPod9,1` and the `iPhone14,2` without requesting user confirmation to download. It will also always try to `resume` previously interrupted downloads and will download everything to the `/SHARE/IPSWs` folder

You can also use environment variables to set `ipsw` config

```bash
❯ IPSW_DOWNLOAD_DEVICE=iPhone14,2 ipsw download ipsw --latest
```