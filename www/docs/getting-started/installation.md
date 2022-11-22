---
description: How to install ipsw locally, and start a parsing IPSWs in no time.
---

# Installation

```mdx-code-block
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';
```

```mdx-code-block
<Tabs>
<TabItem value="macOS">
```

Via [homebrew](https://brew.sh)

```bash
brew install blacktop/tap/ipsw
```

Via binary from the [releases](https://github.com/blacktop/ipsw/releases) page

```bash
https://github.com/blacktop/ipsw/releases/download/v3.1.199/ipsw_3.1.199_macOS_universal.tar.gz
tar xzf ipsw_3.1.199_macOS_universal.tar.gz
```

```mdx-code-block
</TabItem>
<TabItem value="linux">
```

Via [snapcraft](https://snapcraft.io/ipsw)

```bash
sudo snap install ipsw
```

Via `deb`/`rpm`/`apk` debian packages in the [releases](https://github.com/blacktop/ipsw/releases) page

```bash
wget https://github.com/blacktop/ipsw/releases/download/v3.1.199/ipsw_3.1.199_linux_x86_64.deb
sudo dpkg -i ipsw_3.1.199_linux_x86_64.deb
```

Install [archlinux](https://aur.archlinux.org/packages/ipsw-bin/) package from AUR

```bash
pacman -U ipsw-bin
```

```mdx-code-block
</TabItem>
<TabItem value="docker">
```

[![Docker Stars](https://img.shields.io/docker/stars/blacktop/ipsw.svg)](https://hub.docker.com/r/blacktop/ipsw/) [![Docker Pulls](https://img.shields.io/docker/pulls/blacktop/ipsw.svg)](https://hub.docker.com/r/blacktop/ipsw/) [![Docker Image](https://img.shields.io/badge/docker%20image-114MB-blue.svg)](https://hub.docker.com/r/blacktop/ipsw/)

Download docker image

```bash
$ docker pull blacktop/ipsw
```

> **NOTE:** the docker image also includes [apfs-fuse](https://github.com/sgan81/apfs-fuse) which allows you to extract `dyld_shared_caches` from the APFS dmgs in the ipsw(s) pre **iOS16.x**

Create `alias` to use like a binary

```
$ alias ipsw='docker run -it --rm -v $(pwd):/data blacktop/ipsw'
```

```mdx-code-block
</TabItem>
<TabItem value="windows">
```

Via [scoop](https://scoop.sh)

```bash
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket.git 
scoop install blacktop/ipsw
```

Via [chocolatey](https://chocolatey.org)

```bash
choco install ipsw
``` 

```mdx-code-block
</TabItem>
</Tabs>
```