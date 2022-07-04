---
title: "Install"
date: 2020-01-25T21:06:37-05:00
draft: false
weight: 2
summary: How to install
---

## macOS

Via [homebrew](https://brew.sh)

```bash
$ brew install blacktop/tap/ipsw
```

---

## windows

Download from [releases](https://github.com/blacktop/ipsw/releases/latest)

### Via `scoop`

```bash
$ scoop bucket add org https://github.com/blacktop/scoop-bucket.git
$ scoop install blacktop/ipsw
```

---

## linux/docker

### Via Linux [homebrew](https://brew.sh)

```bash
$ brew install blacktop/tap/ipsw
```

### Via [docker](https://www.docker.com)

[![Docker Stars](https://img.shields.io/docker/stars/blacktop/ipsw.svg)](https://hub.docker.com/r/blacktop/ipsw/) [![Docker Pulls](https://img.shields.io/docker/pulls/blacktop/ipsw.svg)](https://hub.docker.com/r/blacktop/ipsw/) [![Docker Image](https://img.shields.io/badge/docker%20image-114MB-blue.svg)](https://hub.docker.com/r/blacktop/ipsw/)

Download docker image

```bash
$ docker pull blacktop/ipsw
```

> **NOTE:** the docker image also includes [apfs-fuse](https://github.com/sgan81/apfs-fuse) which allows you to extract `dyld_shared_caches` from the APFS dmgs in the ipsw(s).

Create `alias` to use like a binary

```
$ alias ipsw='docker run -it --rm -v $(pwd):/data blacktop/ipsw'
```
