---
title: "Build"
date: 2020-01-26T09:47:03-05:00
draft: false
weight: 3
summary: Build from source
---

#### Install the Go binary

```bash
$ git clone https://github.com/blacktop/ipsw.git
$ cd ipsw
$ CGO_ENABLED=0 go build ./cmd/ipsw
```

## **WITHOUT** internet

On internet connected machine with Go installed

```bash
$ go mod vendor
```

Now copy the project's directory to _no-net_ machine

Add `--mod=vendor` to use the Go deps in the vendor folder

```bash
$ go build --mod=vendor ./cmd/ipsw
```
