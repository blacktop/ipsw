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

---

## linux/docker

[![Docker Stars](https://img.shields.io/docker/stars/blacktop/ipsw.svg)](https://hub.docker.com/r/blacktop/ipsw/) [![Docker Pulls](https://img.shields.io/docker/pulls/blacktop/ipsw.svg)](https://hub.docker.com/r/blacktop/ipsw/) [![Docker Image](https://img.shields.io/badge/docker%20image-114MB-blue.svg)](https://hub.docker.com/r/blacktop/ipsw/)

Download docker image

```bash
$ docker pull blacktop/ipsw
```

Create `alias` to use like a binary

```
$ alias ipsw='docker run -it --rm -v $(pwd):/data blacktop/ipsw'
```
