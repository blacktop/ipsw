---
title: "info"
date: 2020-01-26T09:17:25-05:00
draft: false
weight: 6
summary: Display info about IPSW(s).
---

### Display info about IPSWs

```bash
$ ipsw info iPhone12,3_17D5044a_Restore.ipsw

[IPSW Info]
===========
Version        = 13.3.1
BuildVersion   = 17D5044a
OS Type        = "Development"
FileSystem     = 038-19665-018.dmg (Type: APFS)

Devices
-------

iPhone XS Max)
 - iPhone11,6_D331PAP_17D5044a
   - KernelCache: kernelcache.release.iphone11
   - CPU: A12 Bionic (ARMv8.3-A), ID: t8020

iPhone 11 Pro)
 - iPhone12,3_D421AP_17D5044a
   - KernelCache: kernelcache.release.iphone12
   - CPU: A13 Bionic (ARMv8.3-A), ID: t8030

iPhone XS)
 - iPhone11,2_D321AP_17D5044a
   - KernelCache: kernelcache.release.iphone11
   - CPU: A12 Bionic (ARMv8.3-A), ID: t8020

iPhone 11 Pro Max)
 - iPhone12,5_D431AP_17D5044a
   - KernelCache: kernelcache.release.iphone12
   - CPU: A13 Bionic (ARMv8.3-A), ID: t8030
```

### Or remotely

```bash
$ ipsw info --remote https://updates.cdn-apple.com/../iPodtouch_7_13.3_17C54_Restore.ipsw
```