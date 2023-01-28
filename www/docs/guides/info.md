---
description: Get a TON of info about an IPSW/OTA withouth having to even download it.
---

# Parse fireware zip metadata

### Display info about IPSWs and OTAs

```bash
❯ ipsw info iPhone11,2,iPhone11,4,iPhone11,6,iPhone12,3,iPhone12,5_15.0_19A5318f_Restore.ipsw

[IPSW Info]
===========
Version        = 15.0
BuildVersion   = 19A5318f
OS Type        = "Development"
FileSystem     = 018-62379-017.dmg (Type: APFS)

Devices
-------

iPhone XS Max
 > iPhone11,6_D331PAP_19A5318f
   - KernelCache: [kernelcache.release.iphone11]
   - CPU: A12 Bionic (ARMv8.3-A), ID: t8020
   - BootLoaders
       * iBEC.d331p.RELEASE.im4p
       * iBoot.d331p.RELEASE.im4p
       * iBSS.d331p.RELEASE.im4p
       * LLB.d331p.RELEASE.im4p

iPhone 11 Pro
 > iPhone12,3_D421AP_19A5318f
   - KernelCache: [kernelcache.release.iphone12]
   - CPU: A13 Bionic (ARMv8.4-A), ID: t8030
   - BootLoaders
       * iBEC.d421.RELEASE.im4p 🔑 -> cc0b556bbe5295a9ade5c1ee4bee71b732632e560b52c312f1c88c3229c3248229555d90e59d81a54a3a3665d2650774
       * iBoot.d421.RELEASE.im4p 🔑 -> 0a5f2d58b34e32fa0f4253c7a1e45487da4f58c366c6284a0ee8be802805d0b1ef049ba11512982f177a2a7919f5eeb6
       * iBSS.d421.RELEASE.im4p 🔑 -> 23c6c1710556c8b0ea120a64a614c097cad720a3dfe71c7941ccb080a7dbf6e40a7cbf8e9cff4f69b2a505644c5026f4
       * LLB.d421.RELEASE.im4p 🔑 -> a433b0cefa2ed0e9b0d87f5c12b3fadb8d2d6467f6c0b436292c8948e9a7165c72b9fb21de3eafcbfb8b170b444c6444

iPhone 11 Pro Max
 > iPhone12,5_D431AP_19A5318f
   - KernelCache: [kernelcache.release.iphone12]
   - CPU: A13 Bionic (ARMv8.4-A), ID: t8030
   - BootLoaders
       * iBEC.d431.RELEASE.im4p 🔑 -> 5f5209d8cc105cda06a00d4e15f532b397c84ddfe68ae156c5def0eeaf735d80ef735b484790bb2899f3f0cfd7824c5c
       * iBoot.d431.RELEASE.im4p 🔑 -> 6d00b7f25e54a7c63560620db45333e4f26e229362c5896b4592a4825ea344f96b733e042d1bbe0f4217da350c4ab259
       * iBSS.d431.RELEASE.im4p 🔑 -> 5ed92a3e382d225aa929f990084a36defd1d543f11320784cf8b030e5ce8d3389aeab70baf33dd383706135262968ac1
       * LLB.d431.RELEASE.im4p 🔑 -> 24a8f3f960c4e38262a43a6c717d9466fb05a86642c18eca41a55cec7cc6cd66b54bad4c43d5c04f93151a6979b6f7b8

iPhone XS
 > iPhone11,2_D321AP_19A5318f
   - KernelCache: [kernelcache.release.iphone11]
   - CPU: A12 Bionic (ARMv8.3-A), ID: t8020
   - BootLoaders
       * iBEC.d321.RELEASE.im4p
       * iBoot.d321.RELEASE.im4p
       * iBSS.d321.RELEASE.im4p
       * LLB.d321.RELEASE.im4p

iPhone XS Max
 > iPhone11,4_D331AP_19A5318f
   - KernelCache: [kernelcache.release.iphone11]
   - CPU: A12 Bionic (ARMv8.3-A), ID: t8020
   - BootLoaders
       * iBEC.d331.RELEASE.im4p
       * iBoot.d331.RELEASE.im4p
       * iBSS.d331.RELEASE.im4p
       * LLB.d331.RELEASE.im4p

```

### Or remotely

```bash
❯ ipsw info --remote https://updates.cdn-apple.com/../iPodtouch_7_13.3_17C54_Restore.ipsw
```

### To list all the files in a remote IPSW or OTA

```bash
❯ ipsw info --remote https://updates.cdn-apple.com/../iPodtouch_7_13.3_17C54_Restore.ipsw --list

PATH                                                                   SIZE
----                                                                   ----
018-95664-055.dmg                                                      124 MB
018-95777-055.dmg                                                      126 MB
018-95946-047.dmg                                                      6.1 GB
BuildManifest.plist                                                    282 kB
Firmware/                                                              0 B
Firmware/018-95664-055.dmg.trustcache                                  5.3 kB
Firmware/018-95777-055.dmg.trustcache                                  5.4 kB
Firmware/018-95946-047.dmg.mtree                                       32 MB
Firmware/018-95946-047.dmg.root_hash                                   229 B
Firmware/018-95946-047.dmg.trustcache                                  56 kB
<SNIP>
```

### To dump a VERBOSE version of the info summary

```bash
❯ ipsw info OTA -V
```
:::info note
This will also dump out the full BuidManifest.plist, Restore.plist, and Info.plists etc
:::