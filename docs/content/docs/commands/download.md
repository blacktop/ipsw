---
title: "download"
date: 2020-01-25T21:55:35-05:00
weight: 5
summary: Download and parse IPSW(s) from the internets.
---

- [**download**](#download)
- [**download latest**](#download-latest)
- [**download kernel**](#download-kernel)
- [**download pattern**](#download-pattern)
- [**download beta**](#download-beta)
- [**download ota**](#download-ota)

---

> ⚠️ **NOTICE:** Apple seems to be removing old `ipsws` from their CDN servers so if you get a 404 or some other error that might be the reason why.

## **download**

> Queries the [ipsw.me](https://ipsw.me) API

- Download an ipsw and extract/decompress the kernelcache

```bash
$ ipsw download --device iPhone11,2 --build 16A366

   • Getting IPSW              build=16A366 device=iPhone11,2 signed=true version=12.0
      3.4 GiB / 3.4 GiB [==========================================================| 00:00 ] 79.08 MiB/s
      • verifying sha1sum...

$ ipsw extract --kernel iPhone11,2_12.0_16A366_Restore.ipsw

   • Extracting Kernelcache from IPSW
      • Parsing Compressed Kernelcache
         • compressed size: 17842843, uncompressed: 35727352. unknown: 0x3f9543fd, unknown 1: 0x1
      • Decompressing Kernelcache
```

⚠️ notice that the kernelcache was extracted from the ipsw and decompressed 😈

```bash
$ file kernelcache.release.iphone11.decompressed

kernelcache.release.iphone11.decompressed: "Mach-O 64-bit executable arm64"
```

- Download all the iOS 12.0 ipsws

```bash
$ ipsw download --version 12.0

? You are about to download 17 ipsw files. Continue? Yes
   • Getting IPSW              build=16A366 device=iPhone11,4 signed=true version=12.0
    3.3 GiB / 3.3 GiB [==========================================================| 00:00 ] 59.03 MiB/s
      • verifying sha1sum...
   • Getting IPSW              build=16A366 device=iPod7,1 signed=true version=12.0
    734.7 MiB / 2.6 GiB [===============>------------------------------------------| 00:57 ] 44.84 MiB/s
  ...
```

- Download with a Proxy

This will download and decompress the kernelcache for an **iPhone XS** running **iOS 12.1** behind a corporate proxy

```bash
$ ipsw download --proxy http://proxy.org:[PORT] --device iPhone11,2 --build 16B92
```

- To disable cert verification

```bash
$ ipsw download --insecure --device iPhone11,2 --build 16B92
```

## **download latest**

> Queries the iTunes XML for latest version _(maybe run this as a cron job)_ 😉

- Download all the latest ipsws

```bash
$ ipsw download -V latest --yes --black-list AppleTV --black-list iPod7,1
   • Latest iOS release found is: "12.4.1"
      • "Yo, ain't no one jailbreaking this shizz NOT even Ian Beer my dude!!!! 😏"
   • Getting IPSW              build=16G77 device=iPhone6,2 version=12.4.1
        363.0 MiB / 2.9 GiB [======>-----------------------------------------------| 18:52 ] 49.18 MiB/s
  ...
```

This will also generate a `checksums.txt.sha1` file that you can use to verify the downloads

```bash
$ sha1sum -c checksums.txt.sha1

iPad_64bit_TouchID_13.2.3_17B111_Restore.ipsw: OK
iPadPro_9.7_13.2.3_17B111_Restore.ipsw: OK
iPad_Educational_13.2.3_17B111_Restore.ipsw: OK
```

⚠️ **NOTE:** you must do **one** device type/family per `--black-list` or `--white-list` flag

- To grab _only_ the iPods

```bash
$ ipsw download -V latest --yes --white-list ipod
   • Latest iOS release found is: "12.4.1"
      • "Yo, ain't no one jailbreaking this shizz NOT even Ian Beer my dude!!!! 😏"
   • Getting IPSW              build=16G77 device=iPod9,1 version=12.4.1
        363.0 MiB / 2.9 GiB [======>-----------------------------------------------| 18:52 ] 49.18 MiB/s
  ...
```

## **download kernel**

> Queries the [ipsw.me](https://ipsw.me) API

Only download and decompress the kernelcaches _(not supported on Windows)_

- Single kernelcache

```bash
ipsw download kernel --device iPhone11,2 --build 16B92
```

- All of dem!!!

```bash
$ time ipsw download kernel --version 12.0.1

"8.40s user 1.19s system 53% cpu 17.784 total"
```

That's **14** decompressed kernelcaches in under **9 seconds** 😏

```bash
$ ls -1

kernelcache.release.ipad4b.decompressed
kernelcache.release.ipad5b.decompressed
kernelcache.release.ipad6b.decompressed
kernelcache.release.ipad6d.decompressed
kernelcache.release.ipad6f.decompressed
kernelcache.release.ipad7.decompressed
kernelcache.release.iphone10b.decompressed
kernelcache.release.iphone11.decompressed
kernelcache.release.iphone11b.decompressed
kernelcache.release.iphone7.decompressed
kernelcache.release.iphone8b.decompressed
kernelcache.release.iphone9.decompressed
kernelcache.release.j42d.decompressed
kernelcache.release.n102.decompressed
```

## **download pattern**

> Queries the [ipsw.me](https://ipsw.me) API

Only download files that match a given name/path

```bash
$ ipsw download -v 13.4 -d iPhone12,3 pattern iBoot
```

```bash
$ ls iBoot*
iBoot.d321.RELEASE.im4p        iBoot.d331p.RELEASE.im4p.plist
iBoot.d321.RELEASE.im4p.plist  iBoot.d421.RELEASE.im4p
iBoot.d331.RELEASE.im4p        iBoot.d421.RELEASE.im4p.plist
iBoot.d331.RELEASE.im4p.plist  iBoot.d431.RELEASE.im4p
iBoot.d331p.RELEASE.im4p       iBoot.d431.RELEASE.im4p.plist
```

## **download beta**

> This is done by scraping [theiphonewiki.com](https://theiphonewiki.com).

Download BETA ipsws

```bash
$ ipsw download beta 17C5046a
```

## **download ota**

Download **beta** OTA _(over the air updates)_

```bash
$ ipsw download ota --device iPhone12,3
```

Just download the _kernelcache_ and _dyld_shared_cache_

⚠️ **NOTE:** this broke in iOS 14 _(the format has changed again)_

```bash
$ ipsw download ota --device iPod9,1 --kernel --dyld
? You are about to download 1 ipsw files. Continue? Yes
   • Parsing remote OTA        build=17F5054h device=iPod9,1 version=iOS135DevBeta3
   • Extracting remote dyld_shared_cache (can be a bit CPU intensive)
      • Extracting -rwxr-xr-x uid=0, gid=80, 1.7 GB, System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 to "iPod9,1_N112AP_17F5054h/dyld_shared_cache_arm64"
   • Extracting remote kernelcache
      • Parsing Kernelcache IMG4
      • Decompressing Kernelcache
      • Kernelcache is LZFSE compressed
      • Writing "iPod9,1_N112AP_17F5054h/kernelcache.beta"
```
