---
title: "shsh"
date: 2020-03-15T01:32:35-04:00
draft: false
weight: 15
summary: Dump shsh blobs.
---

### Dump shsh blob

#### Setup

[Jailbreak](https://checkra.in/) your iDevice and install openssh

```bash
$ brew install libusbmuxd
```

```bash
$ iproxy 2222 22
```

Dumping shsh blobs allows you to downgrade iOS later.

```bash
$ ipsw shsh

   • Connecting to root@localhost:2222
      • Parsing shsh
      • Parsing IMG4
         • Dumped SHSH blob to 1249767383957670.dumped.shsh
```
