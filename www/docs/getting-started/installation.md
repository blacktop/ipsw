---
description: How to install ipsw locally.
hide_table_of_contents: true
---

# Installation

> How to install ipsw locally, and start a parsing IPSWs in no time.

```mdx-code-block
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';
```

```mdx-code-block
<Tabs>
<TabItem value="macOS">
```

## Via [homebrew](https://brew.sh)

```bash
brew install blacktop/tap/ipsw --with-git-delta
```

:::info 
`--with-git-delta` is optional and will install [git-delta](https://github.com/dandavison/delta) for better looking diffs.
:::

Install `frida` version

```bash
brew install blacktop/tap/ipsw-frida
```

## Via [MacPorts](https://www.macports.org)

```bash
sudo port install ipsw
```

### Install development version

```bash
git clone https://github.com/blacktop/ports ~/.config/macports/blacktop
```

Add the following to the `sources.conf` file:

```bash
sudo echo "file://$HOME/.config/macports/blacktop [default]" >> /opt/local/etc/macports/sources.conf
sudo port selfupdate
```

Then install `ipsw`:

```bash
sudo port install ipsw
```

## Via binary from the [releases](https://github.com/blacktop/ipsw/releases) page

```bash
# Download latest release (replace VERSION with current version from releases page)
wget https://github.com/blacktop/ipsw/releases/latest/download/ipsw_$(curl -s https://api.github.com/repos/blacktop/ipsw/releases/latest | grep -o '"tag_name": "[^"]*' | cut -d'"' -f4 | tr -d 'v')_macOS_universal.tar.gz
tar xzf ipsw_*.tar.gz
```

:::tip Quick Install
You can also visit the [releases page](https://github.com/blacktop/ipsw/releases/latest) to download the latest version directly.
:::

### Extras Version

Want to use the `ipsw dyld emu` *(w/ [unicorn](https://www.unicorn-engine.org) emulator)* or the `ipsw idev` cmds that require `libusb` ? *(grab the **extras** version from the [releases](https://github.com/blacktop/ipsw/releases) page)*

```bash
# Download latest extras version
wget https://github.com/blacktop/ipsw/releases/latest/download/ipsw_$(curl -s https://api.github.com/repos/blacktop/ipsw/releases/latest | grep -o '"tag_name": "[^"]*' | cut -d'"' -f4 | tr -d 'v')_macOS_arm64_extras.tar.gz
tar xzf ipsw_*_extras.tar.gz
```

:::info 
The `extras` version is what is installed via homebrew by default.
:::

### Frida Version

Want to use the `ipsw frida` cmd to trace ObjC methods ? *(grab the **frida** version from the [releases](https://github.com/blacktop/ipsw/releases) page)*

```bash
# Download latest frida version  
wget https://github.com/blacktop/ipsw/releases/latest/download/ipsw_$(curl -s https://api.github.com/repos/blacktop/ipsw/releases/latest | grep -o '"tag_name": "[^"]*' | cut -d'"' -f4 | tr -d 'v')_macOS_arm64_frida.tar.gz
tar xzf ipsw_*_frida.tar.gz
```

:::caution 
The **extras** and **frida** versions of `ipsw` only support macOS for now. *(Please let the author know if you want them supported on your platform)*
:::

```mdx-code-block
</TabItem>
<TabItem value="Linux">
```

## Via [snapcraft](https://snapcraft.io/ipsw)

```bash
sudo snap install ipsw
```

## Via `deb`/`rpm`/`apk` debian packages in the [releases](https://github.com/blacktop/ipsw/releases) page

To install, after downloading the files, run:

```bash
dpkg -i ipsw*.deb
rpm -ivh ipsw*.rpm
apk add --allow-untrusted ipsw*.apk
```

## Install [archlinux](https://aur.archlinux.org/packages/ipsw-bin/) package from AUR

```bash
pacman -U ipsw-bin
```

## Install nix package from [NUR](https://github.com/nix-community/NUR)

See [github:blacktop/nur](https://github.com/blacktop/nur)

## Via binary from the [releases](https://github.com/blacktop/ipsw/releases) page

```bash
# Download latest Linux release
wget https://github.com/blacktop/ipsw/releases/latest/download/ipsw_$(curl -s https://api.github.com/repos/blacktop/ipsw/releases/latest | grep -o '"tag_name": "[^"]*' | cut -d'"' -f4 | tr -d 'v')_linux_x86_64.tar.gz
tar xzf ipsw_*.tar.gz
```

## Required tools for mounting DMGs

To use the `ipsw mount` command on Linux, you'll need:

### For APFS filesystems (iOS 10.3+ and modern iPadOS/macOS)

```bash
# Install apfs-fuse
git clone https://github.com/sgan81/apfs-fuse.git
cd apfs-fuse
make
sudo make install
```

### For HFS+ filesystems (older iOS/iPadOS versions)

HFS+ support uses the native Linux kernel with userspace tools:

```bash
# Ubuntu/Debian
sudo apt-get install hfsprogs

# RHEL/CentOS/Fedora
sudo yum install hfsplus-tools
# or
sudo dnf install hfsplus-tools

# Arch Linux
sudo pacman -S hfsprogs
```

:::info 
IPSW automatically detects the filesystem type in DMG files and uses the appropriate mounting method. APFS is used in iOS 10.3+ and newer, while HFS+ is used in older firmware.
:::

```mdx-code-block
</TabItem>
<TabItem value="Docker">
```

[![Docker Stars](https://img.shields.io/docker/stars/blacktop/ipsw.svg)](https://hub.docker.com/r/blacktop/ipsw/) [![Docker Pulls](https://img.shields.io/docker/pulls/blacktop/ipsw.svg)](https://hub.docker.com/r/blacktop/ipsw/) [![Docker Image](https://img.shields.io/badge/docker%20image-114MB-blue.svg)](https://hub.docker.com/r/blacktop/ipsw/)

## Download docker image

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
<TabItem value="Windows">
```

## Via [scoop](https://scoop.sh)

```bash
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket.git 
scoop install blacktop/ipsw
```

<!-- Via [chocolatey](https://chocolatey.org)

```bash
choco install ipsw
```  -->

## Via binary from the [releases](https://github.com/blacktop/ipsw/releases) page

```bash
# Download latest Windows release
# You can also visit https://github.com/blacktop/ipsw/releases/latest to download manually
curl -L https://github.com/blacktop/ipsw/releases/latest/download/ipsw_$(curl -s https://api.github.com/repos/blacktop/ipsw/releases/latest | grep -o '"tag_name": "[^"]*' | cut -d'"' -f4 | tr -d 'v')_windows_x86_64.tar.gz -o ipsw_windows.tar.gz
tar xzf ipsw_windows.tar.gz
```

```mdx-code-block
</TabItem>
</Tabs>
```
