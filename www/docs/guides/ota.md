---
description: How to extract the files you need from OTAs.
hide_table_of_contents: true
---

# Parse OTAs

#### Download the *latest* beta OTA

```bash
❯ ipsw download ota --platform ios --device iPhone15,2 --beta
```

To only download the OTA's `dyld_shared_cache(s)` and `kernelcache`

```bash
❯ ipsw download ota --platform ios --device iPhone15,2 --beta --dyld --kernel
```

:::caution NOTE
If you are downloading OTAs for iOS16.x or macOS13.x or newer this will only work when ran on a **macOS Ventura** host as it calls into a private API to apply the patch.
:::

To download the latest RSR (Rapid Security Release) OTA

```bash
❯ ipsw download ota --platform ios --device iPhone15,2 --build 20C5049e --beta --rsr
   • Getting iOS 16.2 OTA      build=20C7750490e device=iPhone15,2 model=D73AP type="iOS162BetaRSR"
        92.97 MiB / 92.97 MiB [==========================================================| ✅  ] 58.85 MiB/s
```

:::info
The `--build` flag is required for RSR OTAs
:::

#### Show OTA Info

```bash
❯ ipsw ota info iOS16.2_OTAs/iPhone15,2_1418867a3b673659e7bcd30c3823ff997b4ba990.zip
```
```markdown
[OTA Info]
==========
Version        = 16.2
BuildVersion   = 20C5058d
OS Type        = Beta
FileSystem     = 098-19014-027.dmg (Type: APFS)

Devices
-------

iPhone 14 Pro
 > iPhone15,2_D73AP_20C5058d
   - TimeStamp: 14 Nov 2022 22:15:41 MST
   - KernelCache: kernelcache.release.iphone15
   - CPU: A16 Bionic (ARMv8.6-A), ID: t8120
   - BootLoaders
       * iBEC.d73.RELEASE.im4p
       * iBoot.d73.RELEASE.im4p
       * iBSS.d73.RELEASE.im4p
       * LLB.d73.RELEASE.im4p
       * sep-firmware.d73.RELEASE.im4p
```

#### List files in OTA

```bash
❯ ipsw ota ls OTA.zip | head
   • Listing files in OTA zip...
[ OTA zip files ] --------------------------------------------------
-rw-r--r-- 2022-11-28T05:58:49-07:00 3.9 kB Info.plist
-rw-r--r-- 2022-11-28T05:41:25-07:00 29 MB  post.bom
-rw-r--r-- 2022-11-28T05:41:25-07:00 35 kB  pre.bom
-rw-r--r-- 2022-11-28T05:37:39-07:00 171 kB boot/BuildManifest.plist
-r--r--r-- 2022-11-28T02:54:40-07:00 1.0 kB boot/Restore.plist
-r--r--r-- 2022-11-28T00:43:23-07:00 386 B  boot/RestoreVersion.plist
-r--r--r-- 2022-11-28T00:43:03-07:00 539 B  boot/SystemVersion.plist
-rwxr--r-- 2022-11-18T01:59:39-07:00 20 MB  boot/kernelcache.release.iphone15
-rw-r--r-- 2022-11-28T02:54:39-07:00 229 B  boot/Firmware/098-18456-028.dmg.root_hash
```

See if `dyld` is in the OTA files

```bash
❯ ipsw ota ls iPhone15,2_1418867a3b673659e7bcd30c3823ff997b4ba990.zip | grep dyld
   • Listing files in OTA zip...
   • Listing files in OTA payload...
   • (OTA might not actually contain all these files if it is a partial update file)
-rwxr-xr-x 2022-11-28T00:43:03-07:00 926 kB usr/lib/dyld
```

#### Extract file(s) from OTA zip *or* payloads that match a regex pattern

```bash
❯ ipsw ota extract OTA.zip '^System/Library/.*/dyld_shared_cache.*$'
   • Extracting ^System/Library/.*/dyld_shared_cache.*$...
      • Extracting -rwxr-xr-x   1.5 GB  /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e to iPhone14,2_D63AP_19C5026i/dyld_shared_cache_arm64e
      • Extracting -rwxr-xr-x   787 MB  /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e.1 to iPhone14,2_D63AP_19C5026i/dyld_shared_cache_arm64e.1
      • Extracting -rwxr-xr-x   480 MB  /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e.symbols to iPhone14,2_D63AP_19C5026i/dyld_shared_cache_arm64e.symbols
```

:::info
:new: iOS 16.x/macOS 13.x OTAs now contain a RIDIFF10 cryptex volumes that contain the `dyld_shared_cache` files
:::

#### Extract file(s) from OTA RIDIFF10 cryptex volumes

```bash
❯ ipsw ota patch rsr iPhone15,2_1418867a3b673659e7bcd30c3823ff997b4ba990.zip --output /tmp/PATCHES
   • Patching cryptex-app to /tmp/PATCHES/20C5058d__iPhone15,2/AppOS/098-19380-032.dmg
   • Patching cryptex-system-arm64e to /tmp/PATCHES/20C5058d__iPhone15,2/SystemOS/098-18456-028.dmg
```
```bash
❯ tree /tmp/PATCHES/20C5058d__iPhone15,2/
/tmp/PATCHES/20C5058d__iPhone15,2/
├── AppOS
│   └── 098-19380-032.dmg
└── SystemOS
    └── 098-18456-028.dmg

3 directories, 2 files
```

To extract the `dyld_shared_cache` files from the cryptex volumes, you can now mount the volume and then copy the files out

```bash
❯ open /tmp/PATCHES/20C5058d__iPhone15,2/SystemOS/098-18456-028.dmg # mount the volume
```
```bash
❯ find /Volumes/SydneyCSeed20C5058d.D73DeveloperSystemCryptex/ -name "dyld_shared_cache*" | head
/Volumes/SydneyCSeed20C5058d.D73DeveloperSystemCryptex//System/DriverKit/System/Library/dyld/dyld_shared_cache_arm64e.symbols
/Volumes/SydneyCSeed20C5058d.D73DeveloperSystemCryptex//System/DriverKit/System/Library/dyld/dyld_shared_cache_arm64e
/Volumes/SydneyCSeed20C5058d.D73DeveloperSystemCryptex//System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e.33
/Volumes/SydneyCSeed20C5058d.D73DeveloperSystemCryptex//System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e.34
/Volumes/SydneyCSeed20C5058d.D73DeveloperSystemCryptex//System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e.02
/Volumes/SydneyCSeed20C5058d.D73DeveloperSystemCryptex//System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e.05
/Volumes/SydneyCSeed20C5058d.D73DeveloperSystemCryptex//System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e.04
/Volumes/SydneyCSeed20C5058d.D73DeveloperSystemCryptex//System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e.03
/Volumes/SydneyCSeed20C5058d.D73DeveloperSystemCryptex//System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e.35
/Volumes/SydneyCSeed20C5058d.D73DeveloperSystemCryptex//System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e.32
```


#### How to apply a RSR OTA patch

You must first download and "patch" the base OTA file

```bash
❯ ipsw download ota --platform ios --device iPhone15,2 --beta
```
```bash
❯ ipsw ota patch rsr iPhone15,2_17280b5c6122ee9c11e60081a2610e9766e8b892.zip --output /tmp/PATCHES
   • Patching cryptex-app to /tmp/PATCHES/20C5049e__iPhone15,2/AppOS/098-19380-026.dmg
   • Patching cryptex-system-arm64e to /tmp/PATCHES/20C5049e__iPhone15,2/SystemOS/098-18456-023.dmg
```

Now download the corresponding RSR OTA patch that belongs to the base OTA file

```bash
❯ ipsw download ota --platform ios --device iPhone15,2 --build 20D5024e --beta --rsr
```

:::info
To get the `--build` value, you can use `ipsw download ota --show-latest-build` like so
```bash
❯ ipsw download ota --platform ios --device iPhone15,2 --show-latest-build --beta
"20D5024e"
```
:::

Now apply the patch to the base OTA file

```bash
❯ ipsw ota patch rsr --input /tmp/PATCHES/20C5049e__iPhone15,2 --output /tmp/PATCHES/ RSR_OTA.zip
   • Patching cryptex-app to /tmp/PATCHES/20C7750490e__iPhone15,2/AppOS/098-50146-002.dmg
   • Patching cryptex-system-arm64e to /tmp/PATCHES/20C7750490e__iPhone15,2/SystemOS/098-50080-002.dmg
```

```bash
❯ tree /tmp/PATCHES/20C7750490e__iPhone15,2/ # Notice the new build number
/tmp/PATCHES/20C7750490e__iPhone15,2/
├── AppOS
│   └── 098-50146-002.dmg
└── SystemOS
    └── 098-50080-002.dmg

3 directories, 2 files
```

Now you have the RSR patched files ready to start diffing :smirk: :tada:

:::caution NOTE
For now the `ipsw ota patch rsr` command will only work on **macOS Ventura** as it calls into a private API to apply the patch.  We plan on adding cross-platform support in the future.
:::
