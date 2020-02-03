---
title: "kernel"
date: 2020-01-26T09:17:30-05:00
draft: false
weight: 9
summary: Parse kernelcache.
---

- [**kernel extract**](#kernel-extract)
- [**kernel dec**](#kernel-dec)
- [**kernel kexts**](#kernel-kexts)
- [**kernel diff**](#kernel-diff)

---

### **kernel extract**

Extract and decompress a kernelcache from IPSW

```bash
$ ipsw kernel extract iPodtouch_7_13.3.1_17D5050a_Restore.ipsw
   • Extracting kernelcaches
   • Extracting Kernelcache from IPSW
      • Parsing Kernelcache IMG4
      • Decompressing Kernelcache
      • Kernelcache is LZFSE compressed
      • Created iPod9,1_N112AP_17D5050a/kernelcache.development
```

### **kernel dec**

⚠️ **NOTE:** _not supported on Windows_

Decompress a previously extracted **kernelcache**

```bash
$ ipsw kernel dec kernelcache.release.iphone11
```

### **kernel kexts**

List all the kernelcache's KEXTs

```bash
$ ipsw kernel kexts kernelcache.release.iphone12.decompressed

FOUND: 230
com.apple.kpi.mach (19.2.0)
com.apple.kpi.private (19.2.0)
com.apple.kpi.unsupported (19.2.0)
com.apple.kpi.iokit (19.2.0)
com.apple.kpi.libkern (19.2.0)
com.apple.kpi.bsd (19.2.0)
com.apple.iokit.IONetworkingFamily (3.4)
com.apple.iokit.IOTimeSyncFamily (810.1)
com.apple.iokit.IOPCIFamily (2.9)
com.apple.driver.IOACIPCFamily (1)
com.apple.iokit.IOSkywalkFamily (1)
com.apple.driver.AppleIPAppender (1.0)
<SNIP>
```

### **kernel diff**

🚧 **[WIP]** 🚧

I am playing with the idea of `diffing` kernelcaches by creating directory structures of Apple's src from assert strings.

Then you could use `git diff` or something to get a quick **high** level view of what Apple has changed by seeing new files being added or removed as well as seeing the line numbers of the assert strings move around.

```bash
$ ipsw kernel diff kernelcache.release.iphone11
```

You can see an example of what this outputs [HERE](https://github.com/blacktop/ipsw/tree/master/pkg/kernelcache/diff/Library/Caches/com.apple.xbs/Sources)
