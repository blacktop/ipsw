---
title: "info"
date: 2020-01-26T09:17:25-05:00
draft: false
weight: 6
summary: Display info about IPSW(s).
---

### Display info about IPSWs

```bash
$ ipsw info iPhone11,2,iPhone11,4,iPhone11,6,iPhone12,3,iPhone12,5_15.0_19A5318f_Restore.ipsw

IPSW Info]
===========
Version        = 15.0
BuildVersion   = 19A5318f
OS Type        = "Development"
FileSystem     = 018-62379-017.dmg (Type: APFS)

Devices
-------

Phone 11 Pro
 > iPhone12,3_D421AP_19A5318f
   - BootLoaders
       * iBEC.d421.RELEASE.im4p 🔑 -> cc0b556bbe5295a9ade5c1ee4bee71b732632e560b52c312f1c88c3229c3248229555d90e59d81a54a3a3665d2650774
       * iBoot.d421.RELEASE.im4p 🔑 -> 0a5f2d58b34e32fa0f4253c7a1e45487da4f58c366c6284a0ee8be802805d0b1ef049ba11512982f177a2a7919f5eeb6
   - KernelCache: [kernelcache.release.iphone12]
   - CPU: A13 Bionic (ARMv8.4-A), ID: t8030

iPhone 11 Pro Max
 > iPhone12,5_D431AP_19A5318f
   - BootLoaders
       * iBEC.d431.RELEASE.im4p 🔑 -> 5f5209d8cc105cda06a00d4e15f532b397c84ddfe68ae156c5def0eeaf735d80ef735b484790bb2899f3f0cfd7824c5c
       * iBoot.d431.RELEASE.im4p 🔑 -> 6d00b7f25e54a7c63560620db45333e4f26e229362c5896b4592a4825ea344f96b733e042d1bbe0f4217da350c4ab259
   - KernelCache: [kernelcache.release.iphone12]
   - CPU: A13 Bionic (ARMv8.4-A), ID: t8030

iPhone XS
 > iPhone11,2_D321AP_19A5318f
   - BootLoaders
       * iBEC.d321.RELEASE.im4p
       * iBoot.d321.RELEASE.im4p
   - KernelCache: [kernelcache.release.iphone11]
   - CPU: A12 Bionic (ARMv8.3-A), ID: t8020

iPhone XS Max
 > iPhone11,4_D331AP_19A5318f
   - BootLoaders
       * iBEC.d331.RELEASE.im4p
       * iBoot.d331.RELEASE.im4p
   - KernelCache: [kernelcache.release.iphone11]
   - CPU: A12 Bionic (ARMv8.3-A), ID: t8020

iPhone XS Max
 > iPhone11,6_D331PAP_19A5318f
   - BootLoaders
       * iBEC.d331p.RELEASE.im4p
       * iBoot.d331p.RELEASE.im4p
   - KernelCache: [kernelcache.release.iphone11]
   - CPU: A12 Bionic (ARMv8.3-A), ID: t8020
```

### Or remotely

```bash
$ ipsw info --remote https://updates.cdn-apple.com/../iPodtouch_7_13.3_17C54_Restore.ipsw
```
