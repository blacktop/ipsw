---
title: "Build"
date: 2020-01-26T09:47:03-05:00
draft: false
weight: 3
summary: Build from source
---

### Install the Go binary

```bash
$ git clone https://github.com/blacktop/ipsw.git
$ cd ipsw
$ make build
```

#### To dev and build **WITHOUT** internet

On internet connected machine with Go installed download all Golang lib dependencies

```bash
$ git clone https://github.com/blacktop/ipsw.git
$ cd ipsw
$ go mod vendor # this downloads all of the dependencies into the `vendor` folder
```

Now copy the project's directory to _no-net_ machine

Add `--mod=vendor` to use the Go deps in the vendor folder

```bash
$ go build --mod=vendor ./cmd/ipsw
```

### Build for all supported platforms using [goreleaser](https://goreleaser.com)

```bash
$ git clone https://github.com/blacktop/ipsw.git
$ cd ipsw
$ make dry_release
```
