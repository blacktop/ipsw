---
title: "img4"
date: 2020-03-30T17:48:08-04:00
draft: false
weight: 16
summary: Parse Img4 files.
---

## **img4 dec**

⚠️ **NOTE:** _not supported on Windows_

### Decrypt an `Im4p` file

Download _just_ iBoot

```bash
$ ipsw download pattern -v 13.4 -d iPhone12,3 iBoot
```

Decrypt it with things from tweets 😏

```bash
$ ipsw img4 dec --iv-key <IVKEY> iPhone12,3_D421AP_17E255/iBoot.d421.RELEASE.im4p
   • Parsing Im4p
      • Decrypting file to iPhone12,3_D421AP_17E255/iBoot.d421.RELEASE.im4p.dec
```

It's a thing of beauty 😍

```bash
$ hexdump -C -s 512 -n 80 iPhone12,3_D421AP_17E255/iBoot.d421.RELEASE.im4p.dec

00000200  69 42 6f 6f 74 20 66 6f  72 20 64 34 32 31 2c 20  |iBoot for d421, |
00000210  43 6f 70 79 72 69 67 68  74 20 32 30 30 37 2d 32  |Copyright 2007-2|
00000220  30 31 39 2c 20 41 70 70  6c 65 20 49 6e 63 2e 00  |019, Apple Inc..|
00000230  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000240  52 45 4c 45 41 53 45 00  00 00 00 00 00 00 00 00  |RELEASE.........|
```
