---
description: All the MANY ways and types of files you can download.
---

# Download All Teh Things

:::caution NOTICE
Apple seems to be removing old `ipsws` from their CDN servers so if you get a 404 or some other error that might be the reason why.
:::

## **download ipsw**

> Queries the [ipsw.me](https://ipsw.me) API

Download an IPSW and extract/decompress the kernelcache

```bash
❯ ipsw download ipsw --device iPhone11,2 --build 16A366

   • Getting IPSW              build=16A366 device=iPhone11,2 signed=true version=12.0
      3.4 GiB / 3.4 GiB [==========================================================| 00:00 ] 79.08 MiB/s
      • verifying sha1sum...

❯ ipsw extract --kernel iPhone11,2_12.0_16A366_Restore.ipsw

   • Extracting kernelcaches
      • Created 16A366__iPhone11,2/kernelcache.release.iPhone11,2
```

:::info note
The kernelcache was extracted from the IPSW and decompressed
:::

```bash
❯ file 16A366__iPhone11,2/kernelcache.release.iPhone11,2

16A366__iPhone11,2/kernelcache.release.iPhone11,2 "Mach-O 64-bit executable arm64"
```

Download ALL the **iOS** `12.0` IPSWs

```bash
❯ ipsw download ipsw --version 12.0

? You are about to download 17 ipsw files. Continue? Yes
   • Getting IPSW              build=16A366 device=iPhone11,4 signed=true version=12.0
    3.3 GiB / 3.3 GiB [==========================================================| 00:00 ] 59.03 MiB/s
      • verifying sha1sum...
   • Getting IPSW              build=16A366 device=iPod7,1 signed=true version=12.0
    734.7 MiB / 2.6 GiB [===============>------------------------------------------| 00:57 ] 44.84 MiB/s
  ...
```

Download the **macOS** `11.5` IPSW

```bash
❯ ipsw download ipsw --macos --version 11.5

   • Getting IPSW              build=20G71 device=Macmini9,1 signed=true version=11.5
	16.0 MiB / 13.0 GiB [----------------------------------------------------------| 13h28m42s ]  280.66 KiB/s
  ...
```

Debug speed issues

```bash
❯ ipsw download ipsw --version 15.1 --device iPhone10,1 --verbose
   • URLs to Download:
      • https://updates.cdn-apple.com/2021FallFCS/fullrestores/071-64002/C820E7E5-0168-462E-923A-5C86E217D5B5/iPhone_4.7_P3_15.1_19B74_Restore.ipsw
   • Getting IPSW              build=19B74 device=iPhone10,1 signed=true version=15.1
      • Downloading               file=iPhone_4.7_P3_15.1_19B74_Restore.ipsw
      • URL resolved to: 17.253.17.207 "(Apple Inc - Santa Clara, CA. United States)"
	5.3 MiB / 5.3 GiB [----------------------------------------------------------| 1h18m2s ]  1.17 MiB/s
```

:::info note
The Apple CDN's IP has been geo-looked up and is in **Santa Clara**. You can Ctrl+C and try again for a closer CDN which will typically correlate with increased download speeds.
:::

Download with a Proxy

> This will download and decompress the kernelcache for an **iPhone XS** running **iOS 12.1** behind a corporate proxy

```bash
❯ ipsw download ipsw --proxy http://proxy.org:[PORT] --device iPhone11,2 --build 16B92
```

To disable SSL cert verification

```bash
❯ ipsw download ipsw --insecure --device iPhone11,2 --build 16B92
```

### download `ipsw` config

You can also use a config file with `ipsw` so you don't have to use the flags

```bash
❯ cat ~/.ipsw/config.yml
```

```yaml
download:
  latest: true
  confirm: true
  white-list:
    - iPod9,1
    - iPhone14,2
  resume-all: true
  output: /SHARE/IPSWs
```

> This will download the `latest` IPSWs for _only_ the `iPod9,1` and the `iPhone14,2` without requesting user confirmation to download. It will also always try to `resume` previously interrupted downloads and will download everything to the `/SHARE/IPSWs` folder

You can also use environment variables to set `ipsw` config

```bash
❯ IPSW_DOWNLOAD_DEVICE=iPhone14,2 ipsw download ipsw --latest
```

### **download ipsw --latest**

> Queries the iTunes XML for latest version _(maybe run this as a cron job)_ 😉

Download all the latest IPSWs

```bash
❯ ipsw download ipsw -V --black-list AppleTV --black-list iPod7,1 --latest --confirm
   • Latest iOS release found is: "12.4.1"
      • "Yo, ain't no one jailbreaking this shizz NOT even Ian Beer my dude!!!! 😏"
   • Getting IPSW              build=16G77 device=iPhone6,2 version=12.4.1
        363.0 MiB / 2.9 GiB [======>-----------------------------------------------| 18:52 ] 49.18 MiB/s
  ...
```

> This will also generate a `checksums.txt.sha1` file that you can use to verify the downloads

```bash
❯ sha1sum -c checksums.txt.sha1

iPad_64bit_TouchID_13.2.3_17B111_Restore.ipsw: OK
iPadPro_9.7_13.2.3_17B111_Restore.ipsw: OK
iPad_Educational_13.2.3_17B111_Restore.ipsw: OK
```

:::info note
You must do **one** device type/family per `--black-list` or `--white-list` flag
:::

To grab _only_ the iPods

```bash
❯ ipsw download ipsw --white-list ipod --latest --confirm
   • Latest iOS release found is: "12.4.1"
      • "Yo, ain't no one jailbreaking this shizz NOT even Ian Beer my dude!!!! 😏"
   • Getting IPSW              build=16G77 device=iPod9,1 version=12.4.1
        363.0 MiB / 2.9 GiB [======>-----------------------------------------------| 18:52 ] 49.18 MiB/s
  ...
```

Download **latest** `macOS` IPSWs

```bash
❯ ipsw download ipsw --macos --latest -y

   • Latest release found is: 11.6
   • Getting IPSW              build=20G165 device=Macmini9,1 signed=true version=11.6
	288.6 MiB / 13.0 GiB [>---------------------------------------------------------| 3h30m57s ]  1.03 MiB/s
  ...
```

To just output the latest iOS version

```bash
❯ ipsw download ipsw --show-latest-version

15.1
```

### **download ipsw --kernel**

> Queries the [ipsw.me](https://ipsw.me) API

Only download and decompress the kernelcaches

- Single kernelcache

```bash
❯ ipsw download ipsw --device iPhone11,2 --build 16B92 --kernel
```

- All of dem!!!

```bash
❯ time ipsw download ipsw --version 15.1 --kernel -y

"112.29s user 13.86s system 28% cpu 7:16.35 total" (7m 17s)
```

That's **38** decompressed kernelcaches in under **8 minutess** and I've seen **much** faster _(I miss gigabit internet soooo much)_ 😭

```bash
❯ ls -1 19B74*/kernelcache*
19B74__iPad11,1_2_3_4/kernelcache.release.ipad11
19B74__iPad11,6_7/kernelcache.release.ipad11b
19B74__iPad12,1_2/kernelcache.release.ipad12p
19B74__iPad13,1_2/kernelcache.release.ipad13p
19B74__iPad13,4_5_6_7_8_9_10_11/kernelcache.release.ipad13
19B74__iPad14,1_2/kernelcache.release.ipad14p
19B74__iPad5,1_2_3_4/kernelcache.release.ipad5
<SNIP>
```

### **download ipsw --pattern**

> Queries the [ipsw.me](https://ipsw.me) API

Only download files that match a given name/path

```bash
❯ ipsw download ipsw -d iPhone14,2 --latest --pattern iBoot

   • Latest release found is: 15.1
   • Parsing remote IPSW       build=19B74 device=iPhone14,2 signed=true version=15.1
   • Downloading files that contain: iBoot
      • Created 19B74__iPhone14,2/iBoot.d63.RELEASE.im4p
      • Created 19B74__iPhone14,2/iBoot.d63.RELEASE.im4p.plist
      • Created 19B74__iPhone14,2/iBootData.d63.RELEASE.im4p
      • Created 19B74__iPhone14,2/iBootData.d63.RELEASE.im4p.plist
```

### **download ipsw --ibridge**

Download iBridge firmwares

```bash
❯ ipsw download ipsw --ibridge --latest
   • Latest release found is: 6.2
   • Getting IPSW              build=19P744 device=iBridge2,7 signed=true version=6.2
	50.6 MiB / 577.2 MiB [====>-----------------------------------------------------| 7m20s ]  1.20 MiB/s
```

## **download wiki**

> This is done by scraping [theiphonewiki.com](https://theiphonewiki.com).

Download IPSWs from The iPhone Wiki

```bash
❯ ipsw download wiki --device Watch6,9 --kernel
? You are about to download 4 ipsw files. Continue? Yes
   • Parsing remote IPSW       build=19R346 devices=Watch6,9 version=8.0
   • Extracting remote kernelcache
      • Writing 19R346__Watch6,9/kernelcache.release.Watch6,9
```

:::info note
This depends on the iphonewiki maintainers publishing the IPSW firmware download links.
:::

## **download ota**

Check for availiable OTA _(over the air updates)_ download versions

```bash
❯ ipsw download ota --platform ios --info

? Choose an OS type: iOS
   • OTAs                      type=iOS
   • ⚠️  This includes: iOS, iPadOS, watchOS, tvOS and audioOS (you can filter by adding the --device flag)
      • 15.1.1                    expiration_date=2022-01-30 posting_date=2021-11-01
      • 14.8.1                    expiration_date=2022-01-30 posting_date=2021-10-26
      • 8.1                       expiration_date=2022-01-30 posting_date=2021-10-25
      • 15.1                      expiration_date=2022-01-30 posting_date=2021-10-25
      • 14.8                      expiration_date=2022-01-30 posting_date=2021-10-14
      • 15.0.2                    expiration_date=2022-01-30 posting_date=2021-10-11
      • 5.3.9                     expiration_date=2022-01-23 posting_date=2021-10-11
      • 8.0.1                     expiration_date=2022-01-23 posting_date=2021-10-11
      • 15.0.1                    expiration_date=2022-01-09 posting_date=2021-10-01
      • 12.5.5                    expiration_date=2022-01-30 posting_date=2021-09-23
      • 15.0                      expiration_date=2022-01-23 posting_date=2021-09-20
      • 8.0                       expiration_date=2022-01-09 posting_date=2021-09-20
      • 15.0                      expiration_date=2021-12-30 posting_date=2021-09-20
      • 7.6.2                     expiration_date=2022-01-30 posting_date=2021-09-13
      • 14.8                      expiration_date=2022-01-30 posting_date=2021-09-13
      • 5.3.9                     expiration_date=2022-01-30 posting_date=2021-07-29
      • 6.3                       expiration_date=2022-01-30 posting_date=2021-07-29
      • 7.6.1                     expiration_date=2021-12-12 posting_date=2021-07-29
      • 12.5.4                    expiration_date=2022-01-30 posting_date=2021-07-26
      • 14.7.1                    expiration_date=2022-01-30 posting_date=2021-07-26
      • 14.7                      expiration_date=2021-12-19 posting_date=2021-07-19

```

Download the OTA `14.8.1` release for the `iPhone14,2` device

```bash
❯ ipsw download ota --platform ios --version 14.8.1 --device iPhone10,1

? You are about to download 1 OTA files. Continue? Yes
   • Getting OTA               build=18H107 device=iPhone10,1 version=iOS1481Short
	280.0 MiB / 3.7 GiB [===>------------------------------------------------------| 51m18s ]  1.15 MiB/s
```

Download iOS `15.2` developer **beta** OTA

```bash
❯ ipsw download ota --platform ios --device iPhone12,3 --beta

? You are about to download 1 OTA files. Continue? Yes
   • Getting OTA               build=19C5026i device=iPhone12,3 version=iOS152DevBeta1
	495.3 MiB / 5.8 GiB [====>-----------------------------------------------------| 1h17m52s ]  1.17 MiB/s
```

Download the latest macOS `beta` OTA

```bash
❯ ipsw download ota --platform macos --beta --device Macmini9,1

? You are about to download 1 OTA files. Continue? Yes
   • Getting OTA               build=21C5021h device= version=PreRelease
	143.4 MiB / 775.7 MiB [==========>-----------------------------------------------| 8m51s ]  1.19 MiB/s
```

Download the latest Studio Display `beta` OTA

```bash
❯ ipsw download ota --platform accessory --beta --device AppleDisplay2,1

? You are about to download 1 OTA files. Continue? Yes
   • Getting  15.5 OTA         build=19F5070b device=AppleDisplay2,1 model=J327AP
	143.4 MiB / 775.7 MiB [==========>-----------------------------------------------| 8m51s ]  1.19 MiB/s
```

Just download the _kernelcache_ and _dyld_shared_cache_

```bash
❯ ipsw download ota --platform ios --device iPod9,1 --kernel --dyld
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

You just plucked the `kernelcache` AND THE MUTHA FLIPPIN' `dyld_shared_cache` remotely out of a OTA... ARE YOU NOT ENTERTAINED?!?!!? 😎

## **download macos**

#### List macOS installers

```bash
❯ ipsw download macos --list
```

| TITLE                          | VERSION | BUILD    | POST DATE        |
| ------------------------------ | ------- | -------- | ---------------- |
| macOS Mojave                   | 10.14.5 | 18F2059  | 10Oct19 20:38:26 |
| macOS Mojave                   | 10.14.6 | 18G103   | 10Oct19 20:51:08 |
| macOS High Sierra              | 10.13.6 | 17G66    | 10Oct19 18:19:55 |
| macOS Mojave                   | 10.14.4 | 18E2034  | 10Oct19 14:41:18 |
| Install macOS High Sierra Beta | 10.13.5 | 17F66a   | 10Oct19 14:41:18 |
| macOS Catalina                 | 10.15.3 | 19D2064  | 03Mar20 21:41:00 |
| macOS Catalina                 | 10.15.4 | 19E2269  | 05May20 15:32:04 |
| macOS Catalina                 | 10.15.5 | 19F2200  | 06Jun20 18:52:41 |
| macOS Catalina                 | 10.15.6 | 19G2006  | 08Aug20 23:39:24 |
| macOS Catalina                 | 10.15.6 | 19G2021  | 08Aug20 20:04:02 |
| macOS Catalina                 | 10.15.7 | 19H2     | 09Sep20 17:09:31 |
| macOS Catalina                 | 10.15.7 | 19H4     | 10Oct20 17:28:13 |
| macOS Catalina                 | 10.15.7 | 19H15    | 11Nov20 17:48:09 |
| macOS Big Sur                  | 11.5.1  | 20G80    | 07Jul21 17:10:10 |
| macOS Big Sur                  | 11.5.2  | 20G95    | 08Aug21 18:28:53 |
| macOS Big Sur                  | 11.6    | 20G165   | 09Sep21 18:52:42 |
| macOS Big Sur                  | 11.6.1  | 20G224   | 10Oct21 17:17:27 |
| macOS Monterey                 | 12.0.1  | 21A559   | 10Oct21 17:23:38 |
| macOS Monterey beta            | 12.1    | 21C5021h | 10Oct21 17:04:37 |

#### Download **macOS Monterey**

```bash
❯ ipsw download macos --build 21A559

? You are about to download the macOS Monterey installer files. Continue? Yes
   • Downloading packages
   • Getting Package           destName=BuildManifest.plist size=1.9 MB
	1.9 MiB / 1.9 MiB [==========================================================| ✅  ]  1.17 MiB/s
   • Getting Package           destName=Info.plist size=5.1 kB
	5.0 KiB / 5.0 KiB [==========================================================| ✅  ]  0.00 b/s
   • Getting Package           destName=InstallAssistant.pkg size=12 GB
	74.6 MiB / 11.3 GiB [----------------------------------------------------------| 1h4m28s ]  2.97 MiB/s
```

:::info note
macOS sandboxes certain folders and prevents you from running some of the Apple utils required to build the FULL installers. _(try running in `/Users/Shared`)_
:::

#### To ignore digest verification errors

```bash
❯ ipsw download macos --ignore
```

:::info note
This is probably a bad idea, but I've noticed some of the recent installer parts have bad sha1 digests listed in the sucatalogs
:::

#### To _ONLY_ download the `InstallAssistant.pkg` file _(which includes the install App as well)_

```bash
❯ ipsw download macos --assistant
```

#### To download the latest installer(s)

```bash
❯ ipsw download macos --latest
```

:::info note
This will find the latest installer and then also download any other installers released on the same day.
:::

## **download dev**

Download IPSWs (and more) from https://developer.apple.com/download

```bash
❯ ipsw download dev

? Please type your username: blacktop
? Please type your password: ***********************************
? Please type your verification code: ******
? Choose a download type: OSes (iOS, macOS, tvOS...)
? Choose an OS version: iOS 16.3 beta
? Select what file(s) to download: ✅
   • Downloading               file=iPhone15,2_16.3_20D5024e_Restore.ipsw
        42.11 MiB / 6.27 GiB [----------------------------------------------------------| 20m56s ]  1.54 MiB/s
```

:::info vaults
Your Developer Portal credentials and session are stored securely in your Keychain on macOS; in your Windows Credential Manager on Windows and in your Linux Keyring on Linux.
:::

:::caution note
The `--vault-password` flag is the encryption password for the **file** based vaults that will be placed encrypted in the `~/.ipsw` directory. This is **NOT** for your Developer Portal credentials.

This is when ran on an OS that does not have a native Keychain, Credential Manager or Keyring etc.
:::

Watch for 🆕 **beta** IPSWs

```bash
❯ ipsw download dev --watch 'iOS.*beta'
   • Downloading               file=iPhone11,8,iPhone12,1_15.0_19A5307g_Restore.ipsw
	6.1 GiB / 6.1 GiB [==========================================================| ✅  ]  4.15 MiB/s
   <SNIP>
```

To download all the KDKs

```bash
❯ ipsw download dev --more --watch 'Kernel Debug Kit' --output /path/to/SHARE
   • Downloading               file=/path/to/SHARE/Kernel_Debug_Kit_13.3_build_22E5219e.dmg
	988.41 MiB / 988.41 MiB [================| ✅  ] 16.99 MiB/s
```

:::info NOTE
This will check every 5 minutes for new files and download them.

You can change the timeout with the `--timeout` flag: `--timeout 10m` _(10 minutes)_ or `--timeout 1h` _(1 hour)_
:::

Output downloadable items as JSON

```bash
❯ ipsw download dev --os --json --pretty --output .
   • Creating dev_portal_os.json
```

```bash
❯ cat dev_portal_os.json | jq .
```

```json
{
    "iOS 15.2 beta": [
        {
            "title": "iPhone 13",
            "build": "19C5026i",
            "url": "https://updates.cdn-apple.com/2021FallSeed/fullrestores/002-19786/01936A50-C316-4261-BA24-62EBAF5F1236/iPhone14,5_15.2_19C5026i_Restore.ipsw",
            "type": "ios"
        },
<SNIP>
```

## **download ipa**

Download App Packages from the iOS App Store

```bash
❯ ipsw download ipa --search TikTok
? Select what app(s) to download: ✅
   • Downloading               file=/var/folders/5q/g6x_p_yn113dpvwd1tm2kjzc0000gn/T/appstore.ipa2930715700
	197.74 MiB / 197.74 MiB [==========================================================| ✅  ] 11.68 MiB/s
   • Created com.zhiliaoapp.musically_835599320.v27.4.0.ipa
```

## **download git**

> Download [apple-oss-distributions](https://github.com/apple-oss-distributions) tarballs

Download all latest

```
❯ ipsw download git
```

Download single product

```
❯ ipsw download git --product dyld
```

Supply API token _(to prevent rate limiting)_

```
❯ ipsw download git --api GITHUB_TOKEN
```

:::info note
`ipsw` will also check for env vars `GITHUB_TOKEN`, `GITHUB_API_TOKEN` or `IPSW_DOWNLOAD_GIT_API`
:::

Download repo archive links as JSON

```
❯ ipsw download git --json --output /tmp/git
   • Querying github.com/orgs/apple-oss-distributions for repositories...
   • Adding to JSON            tag=dyld-940
   • Adding to JSON            tag=notify-45.3
   • Adding to JSON            tag=DiskArbitration-366.0.2
   • Adding to JSON            tag=pam_modules-188
```

## **download rss**

> Read Releases - Apple Developer [RSS Feed](https://developer.apple.com/news/)

```
❯ ipsw download rss
```

```md
# Releases - Apple Developer (https://developer.apple.com/news/)

> Apple Developer News and Updates feed provided by Apple, Inc.

---

- Xcode 13.2 beta (13C5066c) <Wed, 27 Oct 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=10272021e
- iOS 15.2 beta (19C5026i) <Wed, 27 Oct 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=10272021d
- iPadOS 15.2 beta (19C5026i) <Wed, 27 Oct 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=10272021c
- watchOS 8.3 beta (19S5026e) <Wed, 27 Oct 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=10272021b
- tvOS 15.2 beta (19K5025g) <Wed, 27 Oct 2021 13:00:00 PDT> https://developer.apple.com/news/releases/?id=10272021a
- Xcode 13.1 (13A1030d) <Mon, 25 Oct 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=10252021f
- macOS Monterey (21A559) <Mon, 25 Oct 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=10252021e
- iOS 15.1 (19B74) <Mon, 25 Oct 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=10252021d
- iPadOS 15.1 (19B74 | 19B75) <Mon, 25 Oct 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=10252021c
- watchOS 8.1 (19R570) <Mon, 25 Oct 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=10252021b
- tvOS 15.1 (19J572) <Mon, 25 Oct 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=10252021a
- App Store Server API Update <Thu, 21 Oct 2021 16:00:00 PDT> https://developer.apple.com/news/releases/?id=10212021g
- App Store Server Notifications Version 2 <Thu, 21 Oct 2021 16:00:00 PDT> https://developer.apple.com/news/releases/?id=10212021ef
- Sandbox Testing Update <Thu, 21 Oct 2021 16:00:00 PDT> https://developer.apple.com/news/releases/?id=10212021e
- App Store Connect Update <Thu, 21 Oct 2021 16:00:00 PDT> https://developer.apple.com/news/releases/?id=10212021d
- App Store Connect API Update <Thu, 21 Oct 2021 16:00:00 PDT> https://developer.apple.com/news/releases/?id=10212021c
- macOS Monterey RC 2 (21A559) <Thu, 21 Oct 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=10212021b
- iOS 15.0.2 (19A404) <Mon, 11 Oct 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=10112021c
- watchOS 8.0.1 (19R354) <Mon, 11 Oct 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=10112021a
- App Store Connect 1.7.1 <Tue, 21 Sep 2021 12:00:00 PDT> https://developer.apple.com/news/releases/?id=09212021f
- Xcode 13 (13A233) <Mon, 20 Sep 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=09202021e
- tvOS 15 (19J346) <Mon, 20 Sep 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=09202021b
- macOS Big Sur 11.6 (20G165) <Mon, 13 Sep 2021 10:00:00 PDT> https://developer.apple.com/news/releases/?id=09132021d
- TestFlight 3.2 beta <Tue, 24 Aug 2021 11:00:00 PDT> https://developer.apple.com/news/releases/?id=08242021a
- TestFlight Submission Update <Tue, 17 Aug 2021 16:00:00 PDT> https://developer.apple.com/news/releases/?id=08172021c
- Transporter 1.2.2 <Thu, 03 Jun 2021 11:00:00 PDT> https://developer.apple.com/news/releases/?id=06032021a
```

Watch for 🆕 Releases

```
❯ ipsw download rss --watch
   • Watching Releases - Apple Developer RSS Feed...
```

This will ping the RSS feed every 5 minutes and create a desktop notification if anything NEW shows up.

## **download tss**

Download SHSH blobs from Apple

```
❯ ipsw download tss
```

:::caution  note
This is still a WIP _(however `signed` check does work)_
:::

Check the signing status of an **iOS** version

```
❯ ipsw download tss --signed 15.0.2
   ⨯ 🔥 15.0.2 is NO LONGER being signed
```

```
❯ ipsw download tss --signed 15.1
   • ✅ 15.1 is still being signed
```
