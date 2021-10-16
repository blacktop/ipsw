---
title: "download"
date: 2020-01-25T21:55:35-05:00
weight: 5
summary: Download and parse IPSW(s) from the internets.
---

- [**download --help**](#download---help)
- [**download**](#download)
- [**download latest**](#download-latest)
- [**download kernel**](#download-kernel)
- [**download pattern**](#download-pattern)
- [**download beta**](#download-beta)
- [**download ota**](#download-ota)
- [**download macos**](#download-macos)
- [**download dev**](#download-dev)
- [**download oss**](#download-oss)

---

> ⚠️ **NOTICE:** Apple seems to be removing old `ipsws` from their CDN servers so if you get a 404 or some other error that might be the reason why.

## **download --help**

Help for download cmd

```bash
❯ ipsw download --help

Download and parse IPSW(s) from the internets

Usage:
  ipsw download [flags]
  ipsw download [command]

Available Commands:
  beta        Download beta IPSWs from theiphonewiki.com
  dev         Download IPSWs (and more) from https://developer.apple.com/download
  kernel      Download just the kernelcache
  latest      Download latest release version
  macos       Download and parse macOS IPSWs
  oss         Download opensource.apple.com file list for macOS version
  ota         Download OTA betas
  pattern     Download files that contain file name part

Flags:
      --black-list stringArray   iOS device black list
  -b, --build string             iOS BuildID (i.e. 16F203)
  -d, --device string            iOS Device (i.e. iPhone11,2)
  -h, --help                     help for download
      --insecure                 do not verify ssl certs
      --proxy string             HTTP/HTTPS proxy
  -_, --remove-commas            replace commas in IPSW filename with underscores
  -s, --skip-all                 Always skip resumable IPSWs
  -v, --version string           iOS Version (i.e. 12.3.1)
      --white-list stringArray   iOS device white list
  -y, --yes                      do not prompt user

Global Flags:
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output

Use "ipsw download [command] --help" for more information about a command.
```

## **download**

> Queries the [ipsw.me](https://ipsw.me) API

- Download an ipsw and extract/decompress the kernelcache

```bash
❯ ipsw download --device iPhone11,2 --build 16A366

   • Getting IPSW              build=16A366 device=iPhone11,2 signed=true version=12.0
      3.4 GiB / 3.4 GiB [==========================================================| 00:00 ] 79.08 MiB/s
      • verifying sha1sum...

❯ ipsw extract --kernel iPhone11,2_12.0_16A366_Restore.ipsw

   • Extracting Kernelcache from IPSW
      • Parsing Compressed Kernelcache
         • compressed size: 17842843, uncompressed: 35727352. unknown: 0x3f9543fd, unknown 1: 0x1
      • Decompressing Kernelcache
```

⚠️ notice that the kernelcache was extracted from the ipsw and decompressed 😈

```bash
❯ file kernelcache.release.iphone11.decompressed

kernelcache.release.iphone11.decompressed: "Mach-O 64-bit executable arm64"
```

- Download all the iOS 12.0 ipsws

```bash
❯ ipsw download --version 12.0

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
❯ ipsw download --proxy http://proxy.org:[PORT] --device iPhone11,2 --build 16B92
```

- To disable cert verification

```bash
❯ ipsw download --insecure --device iPhone11,2 --build 16B92
```

## **download latest**

> Queries the iTunes XML for latest version _(maybe run this as a cron job)_ 😉

- Download all the latest ipsws

```bash
❯ ipsw download -V latest --yes --black-list AppleTV --black-list iPod7,1
   • Latest iOS release found is: "12.4.1"
      • "Yo, ain't no one jailbreaking this shizz NOT even Ian Beer my dude!!!! 😏"
   • Getting IPSW              build=16G77 device=iPhone6,2 version=12.4.1
        363.0 MiB / 2.9 GiB [======>-----------------------------------------------| 18:52 ] 49.18 MiB/s
  ...
```

This will also generate a `checksums.txt.sha1` file that you can use to verify the downloads

```bash
❯ sha1sum -c checksums.txt.sha1

iPad_64bit_TouchID_13.2.3_17B111_Restore.ipsw: OK
iPadPro_9.7_13.2.3_17B111_Restore.ipsw: OK
iPad_Educational_13.2.3_17B111_Restore.ipsw: OK
```

⚠️ **NOTE:** you must do **one** device type/family per `--black-list` or `--white-list` flag

- To grab _only_ the iPods

```bash
❯ ipsw download -V latest --yes --white-list ipod
   • Latest iOS release found is: "12.4.1"
      • "Yo, ain't no one jailbreaking this shizz NOT even Ian Beer my dude!!!! 😏"
   • Getting IPSW              build=16G77 device=iPod9,1 version=12.4.1
        363.0 MiB / 2.9 GiB [======>-----------------------------------------------| 18:52 ] 49.18 MiB/s
  ...
```

- To just output the latest iOS version

```bash
❯ ipsw download latest --info

13.6.1
```

## **download kernel**

> Queries the [ipsw.me](https://ipsw.me) API

Only download and decompress the kernelcaches

- Single kernelcache

```bash
ipsw download kernel --device iPhone11,2 --build 16B92
```

- All of dem!!!

```bash
❯ time ipsw download kernel --version 12.0.1

"8.40s user 1.19s system 53% cpu 17.784 total"
```

That's **14** decompressed kernelcaches in under **9 seconds** 😏

```bash
❯ ls -1

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
❯ ipsw download -v 13.4 -d iPhone12,3 pattern iBoot
```

```bash
❯ ls iBoot*
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
❯ ipsw download beta 17C5046a
```

## **download ota**

Download **iOS15.x developer beta** OTA _(over the air updates)_

```bash
❯ ipsw download ota --device iPhone12,3
```

Just download the _kernelcache_ and _dyld_shared_cache_

```bash
❯ ipsw download ota --device iPod9,1 --kernel --dyld
? You are about to download 1 OTA files. Continue? Yes
   • Parsing remote OTA        build=19A344 device=iPod9,1 version=iOS15Long
   • Extracting remote dyld_shared_cache (can be a bit CPU intensive)
      • Extracting -rwxr-xr-x uid=0, gid=80, 1.7 GB, System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 to "iPod9,1_N112AP_17F5054h/dyld_shared_cache_arm64"
   • Extracting remote kernelcache
      • Parsing Kernelcache IMG4
      • Decompressing Kernelcache
      • Kernelcache is LZFSE compressed
      • Writing "iPod9,1_N112AP_17F5054h/kernelcache.beta"
```

## **download macos**

Download and parse macOS IPSWs

```bash
❯ ipsw download macos --kernel
   • Latest release found is: 11.2.3
? You are about to download 1 ipsw files. Continue? Yes
   • Getting Kernelcache       build=20D91 device=Macmini9,1 version=11.2.3
   • Extracting remote kernelcache
      • Writing ADP3,2_J273AAP_20D91/kernelcache.production
      • Writing ADP3,1_J273AP_20D91/kernelcache.production
      • Writing Macmini9,1_J274AP_20D91/kernelcache.production
      • Writing MacBookPro17,1_J293AP_20D91/kernelcache.production
      • Writing MacBookAir10,1_J313AP_20D91/kernelcache.production
      • Writing iProd99,1_T485AP_20D91/kernelcache.production
```

## **download dev**

Download IPSWs (and more) from https://developer.apple.com/download

```bash
❯ ipsw download dev

? Please type your username: blacktop
? Please type your password: ***********************************
? Please type your verification code: ******
? Choose a download type: "beta"
? Choose an OS version: "macOS Monterey beta 2"
? Select what file(s) to download: "Mac computers with the M1 chip"

   • Downloading               file="UniversalMac_12.0_21A5268h_Restore.ipsw"
        65.9 MiB / 12.8 GiB [----------------------------------------------------------| 2h20m56s ]  1.54 MiB/s
```

Watch for 🆕 **beta** IPSWs

```bash
ipsw download dev --beta --watch iPadOS --watch iOS --watch macOS
? Please type your username: blacktop
? Please type your password: ***********************************
? Please type your verification code: ******
   • Downloading               file=iPhone11,8,iPhone12,1_15.0_19A5307g_Restore.ipsw
	6.1 GiB / 6.1 GiB [==========================================================| ✅  ]  4.15 MiB/s
   <SNIP>
```

> **NOTE:** This will check every 5 minutes for new files and download them. (I've seem apple expire the session and am not sure how to prevent it yet.)

## **download oss**

> Download [opensource.apple.com](https://opensource.apple.com) file for macOS version

Download them all

```
❯ ipsw download oss --macos 11.4 --all
```

Download single product

```
❯ ipsw download oss --macos 11.4 --product dyld
```

List all downloads

```
❯ ipsw download oss --macos 11.4
```

```json
{
   "build": "GoldenGateF20F71",
   "inherits": "GoldenGateE20E232",
   "projects": {
      "AppleFileSystemDriver": {
         "version": "27",
         "url": "https://opensource.apple.com/tarballs/AppleFileSystemDriver/AppleFileSystemDriver-27.tar.gz"
      },
      <SNIP>
      "xar": {
         "version": "452",
         "url": "https://opensource.apple.com/tarballs/xar/xar-452.tar.gz"
      },
      "xnu": {
         "version": "7195.121.3",
         "url": "https://opensource.apple.com/tarballs/xnu/xnu-7195.121.3.tar.gz"
      },
      "zip": {
         "version": "18",
         "url": "https://opensource.apple.com/tarballs/zip/zip-18.tar.gz"
      },
      "zlib": {
         "version": "76",
         "url": "https://opensource.apple.com/tarballs/zlib/zlib-76.tar.gz"
      },
      "zsh": {
         "version": "87",
         "url": "https://opensource.apple.com/tarballs/zsh/zsh-87.tar.gz"
      }
   }
}
```
