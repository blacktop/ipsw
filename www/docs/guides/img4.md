---
description: Parse img4, im4p, im4m etc.
---

# Parse Img4

## **img4 dec**

### Decrypt an `Im4p` file

Download _just_ iBoot

```bash
❯ ipsw download pattern -v 13.4 -d iPhone12,3 iBoot
```

Decrypt it with things from tweets 😏

```bash
❯ ipsw img4 dec --iv-key <IVKEY> iPhone12,3_D421AP_17E255/iBoot.d421.RELEASE.im4p
   • Parsing Im4p
      • Detected LZFSE compression
      • Decrypting file to iPhone12,3_D421AP_17E255/iBoot.d421.RELEASE.im4p.dec
```

It's a thing of beauty 😍

```bash
❯ hexdump -C -s 512 -n 144 iPhone12,3_D421AP_17E255/iBoot.d421.RELEASE.im4p.dec

00000200  69 42 6f 6f 74 20 66 6f  72 20 64 34 32 31 2c 20  |iBoot for d421, |
00000210  43 6f 70 79 72 69 67 68  74 20 32 30 30 37 2d 32  |Copyright 2007-2|
00000220  30 31 39 2c 20 41 70 70  6c 65 20 49 6e 63 2e 00  |019, Apple Inc..|
00000230  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000240  52 45 4c 45 41 53 45 00  00 00 00 00 00 00 00 00  |RELEASE.........|
00000250  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000280  69 42 6f 6f 74 2d 35 35  34 30 2e 31 30 32 2e 34  |iBoot-5540.102.4|
```

## **img4 extract**

### Ever wonder how to mount the RAM disks in the IPSW ?

```bash
❯ ipsw info iPhone15,2_16.3_20D47_Restore.ipsw

[IPSW Info]
===========
Version        = 16.3
BuildVersion   = 20D47
OS Type        = Production
FileSystem     = 098-24861-056.dmg
SystemOS       = 098-24573-060.dmg
AppOS          = 098-24753-064.dmg
RestoreRamDisk = [098-24758-064.dmg 098-25526-064.dmg]
<SNIP>
```

The RestoreRamDisk DMGs `098-24758-064.dmg` and `098-25526-064.dmg` are the `arm64eCustomerRamDisk` and the `arm64eUpdateRamDisk`, however, you cannot mount them as they are actually **im4p** files. 😕

You can now extract the Img4 payloads with the following command:

```bash
❯ unzip -p iPhone15,2_16.3_20D47_Restore.ipsw 098-25526-064.dmg > 098-25526-064.dmg
```
```bash
❯ ipsw img4 extract 098-25526-064.dmg
   • Parsing Im4p
      • Exracting payload to file 098-25526-064.dmg.payload
```

Rename the `payload` back to a _DMG_

```bash
❯ mv 098-25526-064.dmg.payload 098-25526-064.dmg.payload.dmg
```

And now you can open the 🆕 _DMG_ to mount the RAM disk image.

```bash
❯ open 098-25526-064.dmg.payload.dmg
```
```bash
❯ ls -l /Volumes/SydneyD20D47.arm64eUpdateRamDisk/
total 0
drwxr-xr-x   5 blacktop  staff  160 Jan 28 12:35 System
drwxr-xr-x   8 blacktop  staff  256 Jan 13 21:39 bin
dr-xr-xr-x   2 blacktop  staff   64 Dec 16 20:57 dev
lrwxr-xr-x   1 blacktop  staff   11 Jan 13 21:39 etc -> private/etc
drwxr-xr-x   4 blacktop  staff  128 Jan 28 12:40 mnt1
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt2
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt3
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt4
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt5
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt6
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt7
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt8
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt9
drwxr-xr-x   5 blacktop  staff  160 Jan 28 12:39 private
drwxr-xr-x  16 blacktop  staff  512 Jan 13 21:39 sbin
drwxr-xr-x  10 blacktop  staff  320 Jan 28 12:37 usr
lrwxr-xr-x   1 blacktop  staff   11 Jan 13 21:39 var -> private/var
```

:::info note
This is one of the last places you can find the individual framework dylibs
```bash
❯ ls -l /Volumes/SydneyD20D47.arm64eUpdateRamDisk/System/Library/Frameworks/

total 0
drwxr-xr-x  5 blacktop  staff  160 Jan 13 21:39 CFNetwork.framework
drwxr-xr-x  4 blacktop  staff  128 Jan 13 21:39 Combine.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 CoreFoundation.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 CoreServices.framework
drwxr-xr-x  4 blacktop  staff  128 Jan 13 21:39 Foundation.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 IOKit.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 IOSurface.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 MobileCoreServices.framework
drwxr-xr-x  4 blacktop  staff  128 Jan 13 21:39 Network.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 Security.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 SystemConfiguration.framework
```
:::

## **img4 kbags**

### Extract keybags from im4p

```bash
❯ ipsw img4 kbag iBoot.ipad6f.RELEASE.im4p
   • Parsing Im4p

Keybags:
-
  type: PRODUCTION
    iv: e59e7976e1f88c7a3e76c22c75f518ff
   key: 9daae21aeb6189554aa9acb67e229dfc67ec3d04f2f881c2929ff58663cece96
-
  type: DEVELOPMENT
    iv: 510a264622ca1f66909f57fd65405c9c
   key: 7a65aeb58f7900283539388f12ca0930170747ffbe4db10f8a775aaf25636bbb
```
