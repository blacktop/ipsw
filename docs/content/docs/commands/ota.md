---
title: "ota"
date: 2020-02-23T21:07:22-05:00
draft: false
weight: 14
summary: Parse OTA zip files.
---

#### Show OTA Info

```bash
$ ipsw ota --info OTA.zip

[OTA Info]
==========
Version        = 13.5
BuildVersion   = 17F5054h
OS Type        = Beta

Devices
-------

iPhone SE (2nd generation))
 - iPhone12,8_D79AP_17F5054h
   - KernelCache: kernelcache.release.iphone12c
```

#### List files in OTA

```bash
$ ipsw ota OTA.zip | head
   • Listing files...
-rw-r--r-- 2020-02-15T02:24:26-05:00 0 B    .Trashes
---------- 2020-02-15T02:20:25-05:00 0 B    .file
-rwxr-xr-x 2020-02-15T02:23:53-05:00 0 B    etc
-rwxr-xr-x 2020-02-15T02:24:07-05:00 0 B    tmp
-rwxr-xr-x 2020-02-15T02:24:11-05:00 0 B    var
-rwxrwxr-x 2020-02-15T02:20:25-05:00 109 kB Applications/AXUIViewService.app/AXUIViewService
-rw-rw-r-- 2020-02-15T02:20:25-05:00 621 B  Applications/AXUIViewService.app/AXUIViewService-Entitlements.plist
-rw-rw-r-- 2020-02-15T02:20:26-05:00 22 kB  Applications/AXUIViewService.app/Assets.car
-rw-rw-r-- 2020-02-15T02:20:26-05:00 1.5 kB Applications/AXUIViewService.app/Info.plist
-rw-rw-r-- 2020-02-15T02:20:26-05:00 8 B    Applications/AXUIViewService.app/PkgInfo
```

See if `dyld` is in the OTA files

```bash
$ ipsw ota OTA.zip | grep dyld
   • Listing files...
-rwxr-xr-x 2020-02-15T02:22:01-05:00 1.7 GB System/Library/Caches/com.apple."dyld/dyld"_shared_cache_arm64e
-rwxr-xr-x 2020-02-15T02:24:08-05:00 721 kB usr/lib/"dyld"
```

#### Extract file(s) from OTA payloads

```bash
$ ipsw ota OTA.zip dyld_shared_cache
   • Extracting dyld_shared_cache...
      • Extracting -rwxr-xr-x uid=0, gid=80, 1.7 GB, System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e
```

**NOTE:** you can supply a pattern/substring to match
