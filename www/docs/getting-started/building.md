---
description: How to build ipsw from source.
hide_table_of_contents: true
---

# Building

> How to build ipsw from source.

## Requirements {#requirements}

- [Golang](https://go.dev/dl/) *1.22+*

```mdx-code-block
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';
```

```mdx-code-block
<Tabs>
<TabItem value="macOS">
```

## Install the Go binary

```bash
brew install go
```

## Build the `ipsw` binary

```bash
git clone https://github.com/blacktop/ipsw.git
cd ipsw
make build
```

## Build for all supported platforms using [goreleaser](https://goreleaser.com) and [zig](https://ziglang.org)

Get *goreleaser* and *zig*

```bash
brew install goreleaser zig unicorn libusb
```

Build for all supported platforms

```bash
git clone https://github.com/blacktop/ipsw.git
cd ipsw
make snapshot
```

:::info offline

### To dev and build *WITHOUT* internet

On internet connected machine with Go installed download all Golang lib dependencies

```bash
git clone https://github.com/blacktop/ipsw.git
cd ipsw
go mod vendor # this downloads all of the dependencies into the `vendor` folder
```

Now copy the project's directory to _no-net_ machine

Add `--mod=vendor` to use the Go deps in the vendor folder

```bash
CGO_ENABLED=1 go build --mod=vendor ./cmd/ipsw
```

:::

```mdx-code-block
</TabItem>
<TabItem value="Linux">
```
## Install the Golang

```bash
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt update
sudo apt install -y golang-go
```

:::info [apfs-fuse](https://github.com/sgan81/apfs-fuse)

For many of the `ipsw` commands you will need to be able to `mount` DMGs and this is done via [apfs-fuse](https://github.com/sgan81/apfs-fuse)

```bash
sudo apt-get update
sudo apt-get install -y libbz2-dev libz-dev cmake build-essential libattr1-dev libfuse3-dev fuse3 tzdataxz-utils bzip2 unzip lzma
cd /tmp
git clone https://github.com/sgan81/apfs-fuse.git
cd apfs-fuse
git submodule init
git submodule update
mkdir build
cd build
cmake ..
sudo make install
```
:::

## Get the `ipsw` source

```bash
git clone https://github.com/blacktop/ipsw.git
cd ipsw
```

## Build the `ipsw` binary

Build the ipsw *CLI* binary

```bash
sudo CGO_ENABLED=1 go build -o /usr/local/bin/ipsw ./cmd/ipsw
```

## Build the `ipswd` binary

Build the ipsw *daemon* binary

```bash
sudo CGO_ENABLED=1 go build -o /usr/local/bin/ipswd ./cmd/ipswd
```

```mdx-code-block
</TabItem>
</Tabs>
```