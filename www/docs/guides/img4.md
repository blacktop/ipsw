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

### Ever wonder how to mount the RAM disks in the _ipsw_ ?

```bash
❯ unzip -l iPhone11,8,iPhone12,1_14.0_18A5319i_Restore.zip | grep dmg
107235355  01-09-2007 09:41   038-44087-104.dmg
104157211  01-09-2007 09:41   038-44135-103.dmg
5041226384  01-09-2007 09:41   038-44337-066.dmg
     5041  01-09-2007 09:41   Firmware/038-44087-104.dmg.trustcache
     4865  01-09-2007 09:41   Firmware/038-44135-103.dmg.trustcache
  8574971  01-09-2007 09:41   Firmware/038-44337-066.dmg.mtree
       99  01-09-2007 09:41   Firmware/038-44337-066.dmg.root_hash
    49173  01-09-2007 09:41   Firmware/038-44337-066.dmg.trustcache
```

The **BIG** one _(4.7G)_ is the _file system_ (aka the one that has the _dyld_shared_cache_).

The other two are the `arm64eCustomerRamDisk` and the `arm64eUpdateRamDisk`, however, you cannot mount them as they are actually **im4p** files. 😕

You can now extract the Img4 payloads with the following command:

```bash
❯ unzip -p iPhone_4.7_14.0_18A5319i_Restore.ipsw 038-44087-104.dmg > 038-44087-104.dmg
❯ ipsw img4 extract 038-44087-104.dmg
   • Parsing Im4p
      • Exracting payload to file 038-44087-104.dmg.payload
```

Rename the `payload` back to a _DMG_

```bash
❯ mv 038-44087-104.dmg.payload 038-44087-104.dmg.payload.dmg
```

And now you can open the 🆕 _DMG_ to mount the RAM disk image.

```bash
❯ open 038-44087-104.dmg.payload.dmg
❯ ls -l /Volumes/AzulSeed18A5319i.arm64eUpdateRamDisk/
total 16
drwxrwxr-x  3 blacktop  staff  102 Jul  2 02:15 Library
drwxr-xr-x  4 blacktop  staff  136 Jul  2 02:15 System
drwxr-xr-x  2 blacktop  staff  272 Jul  2 02:15 bin
dr-xr-xr-x  2 blacktop  staff   68 Jul  2 02:15 dev
lrwxr-xr-x  1 blacktop  staff   11 Jul  2 02:15 etc -> private/etc
drwxr-xr-x  2 blacktop  staff   68 Jul  2 02:15 mnt1
drwxr-xr-x  2 blacktop  staff   68 Jul  2 02:15 mnt2
drwxr-xr-x  2 blacktop  staff   68 Jul  2 02:15 mnt3
drwxr-xr-x  2 blacktop  staff   68 Jul  2 02:15 mnt4
drwxr-xr-x  2 blacktop  staff   68 Jul  2 02:15 mnt5
drwxr-xr-x  2 blacktop  staff   68 Jul  2 02:15 mnt6
drwxr-xr-x  2 blacktop  staff   68 Jul  2 02:15 mnt7
drwxr-xr-x  2 blacktop  staff   68 Jul  2 02:15 mnt8
drwxr-xr-x  2 blacktop  staff   68 Jul  2 02:15 mnt9
drwxr-xr-x  4 blacktop  staff  136 Jul  2 02:15 private
drwxr-xr-x  2 blacktop  staff  544 Jul  2 02:15 sbin
drwxr-xr-x  9 blacktop  staff  306 Jul  2 02:15 usr
lrwxr-xr-x  1 blacktop  staff   11 Jul  2 02:15 var -> private/var
```
