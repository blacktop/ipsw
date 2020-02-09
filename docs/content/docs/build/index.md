---
title: "Build"
date: 2020-01-26T09:47:03-05:00
draft: false
weight: 3
summary: Build from source
---

## **WITH** support for **lzfse** compression and **capstone** disassembly

#### Dependancies:

- [lzfse](https://github.com/lzfse/lzfse)
- [capstone](https://github.com/aquynh/capstone/tree/next)

### Install the dependancies

Via [homebrew](https://brew.sh)

```bash
$ brew install lzfse
$ brew install capstone --HEAD
```

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

- [capstone](https://github.com/aquynh/capstone/tree/next)

```bash
$ git clone -b next https://github.com/aquynh/capstone.git
$ cd capstone
$ CAPSTONE_ARCHS="arm aarch64" ./make.sh
$ sudo ./make.sh install
```

#### Install the Go binary

```bash
$ git clone https://github.com/blacktop/ipsw.git
$ cd ipsw
$ CGO_ENABLED=1 \
  CGO_CFLAGS=-I/usr/local/include \ # path to the lzfse and capstone includes
  CGO_LDFLAGS=-L/usr/local/lib \    # path to the lzfse and capstone libs
  go build ./cmd/ipsw
```

## **WITHOUT** support for **lzfse** compression and **capstone** disassembly

#### Install the Go binary

```bash
$ git clone https://github.com/blacktop/ipsw.git
$ cd ipsw
$ CGO_ENABLED=0 go build ./cmd/ipsw
```

## **WITHOUT** internet

Add `--mod=vendor` to use the Go deps in the vendor folder

```bash
$ go build --mod=vendor ./cmd/ipsw
```
