---
title: "Build"
date: 2020-01-26T09:47:03-05:00
draft: false
weight: 3
summary: Build from source
---

### Build with support for **lzfse** compression and **capstone** _ARM64_ disassembly

#### Dependancies:

- [lzfse](https://github.com/lzfse/lzfse)
- [capstone](https://github.com/aquynh/capstone/tree/next)

### Install the dependancies

#### Via [homebrew](https://brew.sh)

```bash
$ brew install lzfse
$ brew install capstone --HEAD
```

#### From source

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
$ CAPSTONE_ARCHS="arm aarch64 x86" ./make.sh
$ sudo ./make.sh install
```

## Install the Go binary

```bash
$ CGO_ENABLED=1 \
  CGO_CFLAGS=-I/usr/local/include \ # path to the lzfse and capstone includes
  CGO_LDFLAGS=-L/usr/local/lib \    # path to the lzfse and capstone libs
  go build ./cmd/ipsw
```

### Build **WITHOUT** support for **lzfse** compression and **capstone** _ARM64_ disassembly

## Install the Go binary

```bash
$ CGO_ENABLED=0 go build ./cmd/ipsw
```

#### Sooooo easy... man I hate cgo so much 🤬