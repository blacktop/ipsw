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
- [**kernel sb**](#kernel-sb)
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

### **kernel sb**

List kernel sandbox operations

```bash
$ ipsw kernel sb 18A8395/kernelcache > sb.txt # iOS 14.1
```

```bash
$ ipsw kernel sb 18E5178a/kernelcache > sb.txt # iOS 14.5beta4
```

```bash
$ git diff --no-index sb.txt sb1.txt
```

```diff
diff --git a/sb.txt b/sb1.txt
index b682adf..7492255 100644
--- a/sb.txt
+++ b/sb1.txt
@@ -89,7 +89,10 @@ mach-priv*
 mach-priv-host-port
 mach-priv-task-port
 mach-register
+mach-task*
+mach-task-inspect
 mach-task-name
+mach-task-read
 network*
 network-inbound
 network-bind
@@ -100,9 +103,16 @@ nvram-get
 nvram-set
 opendirectory-user-modify
 process*
+process-codesigning*
+process-codesigning-blob-get
+process-codesigning-cdhash-get
+process-codesigning-entitlements-blob-get
+process-codesigning-identity-get
 process-codesigning-status*
 process-codesigning-status-set
 process-codesigning-status-get
+process-codesigning-teamid-get
+process-codesigning-text-offset-get
 process-exec*
 process-exec-interpreter
 process-fork
@@ -119,6 +129,9 @@ process-info-setcontrol
 pseudo-tty
 signal
 socket-ioctl
+socket-option*
+socket-option-get
+socket-option-set
 sysctl*
 sysctl-read
 sysctl-write
@@ -127,6 +140,7 @@ system-acct
 system-audit
 system-automount
 system-debug
+system-fcntl
 system-fsctl
 system-info
 system-kext*
```

### **kernel diff**

🚧 **[WIP]** 🚧

I am playing with the idea of `diffing` kernelcaches by creating directory structures of Apple's src from assert strings.

Then you could use `git diff` or something to get a quick **high** level view of what Apple has changed by seeing new files being added or removed as well as seeing the line numbers of the assert strings move around.

```bash
$ ipsw kernel diff kernelcache.release.iphone11
```

You can see an example of what this outputs [HERE](https://github.com/blacktop/ipsw/tree/master/pkg/kernelcache/diff/Library/Caches/com.apple.xbs/Sources)
