---
title: "Build"
date: 2020-01-26T09:47:03-05:00
draft: false
weight: 3
summary: Build from source
---

## **WITH** support for **lzfse** decompression

#### Dependancies:

- [lzfse](https://github.com/lzfse/lzfse)

### Install the dependancies

From source

- [lzfse](https://github.com/lzfse/lzfse)

```bash
$ git clone https://github.com/lzfse/lzfse.git
$ cd lzfse
$ mkdir build
$ cd build
$ cmake ..
$ make install
```

#### Install the Go binary

```bash
$ git clone https://github.com/blacktop/ipsw.git
$ cd ipsw
$ CGO_ENABLED=1 \
  CGO_CFLAGS=-I/usr/local/include \ # path to the lzfse includes
  CGO_LDFLAGS=-L/usr/local/lib \    # path to the lzfse libs
  go build ./cmd/ipsw
```

## **WITHOUT** support for **lzfse** decompression

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
