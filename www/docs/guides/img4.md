---
description: Parse img4, im4p, im4m etc.
---

# Parse Img4

The `ipsw img4` command provides comprehensive tools for parsing, manipulating, and creating IMG4 files and their components (IM4P, IM4M, IM4R).

## `ipsw img4 info`

Display detailed information about an IMG4 file.

```bash
# Display information about an IMG4 file
❯ ipsw img4 info kernel.img4

# Output information as JSON
❯ ipsw img4 info --json kernel.img4
```

## `ipsw img4 create`

Create an IMG4 file from various components. This is a powerful new feature allowing you to assemble IMG4 files from raw data or existing IM4P, IM4M, and IM4R files.

### Supported Compression Types

- **`lzss`**
- **`lzfse`**
- **`lzfse_iboot`** - LZFSE compression optimized for iBoot (macOS only)

```bash
# Create IMG4 from existing IM4P with manifest and restore info
❯ ipsw img4 create --im4p payload.im4p --im4m manifest.im4m --im4r restore.im4r --output kernel.img4

# Create IMG4 from raw kernel with LZSS compression and manifest
❯ ipsw img4 create --input kernelcache --type krnl --compress lzss --im4m manifest.im4m --output kernel.img4

# Create IMG4 with boot nonce (generates IM4R automatically)
❯ ipsw img4 create --input sep-firmware.bin --type sepi --boot-nonce 1234567890abcdef --im4m manifest.im4m --output sep.img4

# Create IMG4 with extra data (extra data requires --compress lzss or lzfse)
❯ ipsw img4 create --input payload.bin --type logo --compress lzss --extra extra.bin --im4m manifest.im4m --output logo.img4

# Create unsigned IMG4 (no manifest) - for testing only
❯ ipsw img4 create --input test.bin --type test --output test.img4
```

## `ipsw img4 extract`

Extract components (IM4P, IM4M, IM4R) from an IMG4 file.

```bash
# Extract IM4P payload from IMG4 file
❯ ipsw img4 extract --im4p kernel.img4

# Extract manifest and restore info
❯ ipsw img4 extract --im4m --im4r kernel.img4

# Extract all components to a specific directory
❯ ipsw img4 extract --im4p --im4m --im4r --output /tmp/extracted kernel.img4

# Extract raw (compressed) IM4P data without decompression
❯ ipsw img4 extract --im4p --raw kernel.img4
```

### Ever wonder how to mount the RAM disks in the IPSW ?

```bash
❯ ipsw info iPhone15,2_16.3_20D47_Restore.ipsw

[IPSW Info]
===========
Version        = 16.3
BuildVersion   = 20D47
OS Type        = Production
FileSystem     = 098-24861-056.dmg
SystemOS       = 098-24573-060.dmg
AppOS          = 098-24753-064.dmg
RestoreRamDisk = [098-24758-064.dmg 098-25526-064.dmg]
<SNIP>
```

The RestoreRamDisk DMGs `098-24758-064.dmg` and `098-25526-064.dmg` are the `arm64eCustomerRamDisk` and the `arm64eUpdateRamDisk`, however, you cannot mount them as they are actually **im4p** files. 😕

You can now extract the Img4 payloads with the following command:

```bash
❯ unzip -p iPhone15,2_16.3_20D47_Restore.ipsw 098-25526-064.dmg > 098-25526-064.dmg
```
```bash
# Extract IM4P payload from IMG4 file
❯ ipsw img4 extract --im4p 098-25526-064.dmg
   • Parsing Im4p
      • Exracting payload to file 098-25526-064.dmg.im4p
```

Rename the `payload` back to a _DMG_
```bash
❯ mv 098-25526-064.dmg.im4p 098-25526-064.dmg.im4p.dmg
```

And now you can open the 🆕 _DMG_ to mount the RAM disk image.

```bash
❯ open 098-25526-064.dmg.im4p.dmg
```
```bash
❯ ls -l /Volumes/SydneyD20D47.arm64eUpdateRamDisk/
total 0
drwxr-xr-x   5 blacktop  staff  160 Jan 28 12:35 System
drwxr-xr-x   8 blacktop  staff  256 Jan 13 21:39 bin
dr-xr-xr-x   2 blacktop  staff   64 Dec 16 20:57 dev
lrwxr-xr-x   1 blacktop  staff   11 Jan 13 21:39 etc -> private/etc
drwxr-xr-x   4 blacktop  staff  128 Jan 28 12:40 mnt1
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt2
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt3
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt4
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt5
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt6
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt7
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt8
drwxr-xr-x   2 blacktop  staff   64 Dec  8  2020 mnt9
drwxr-xr-x   5 blacktop  staff  160 Jan 28 12:39 private
drwxr-xr-x  16 blacktop  staff  512 Jan 13 21:39 sbin
drwxr-xr-x  10 blacktop  staff  320 Jan 28 12:37 usr
lrwxr-xr-x   1 blacktop  staff   11 Jan 13 21:39 var -> private/var
```

:::info note
This is one of the last places you can find the individual framework dylibs
```bash
❯ ls -l /Volumes/SydneyD20D47.arm64eUpdateRamDisk/System/Library/Frameworks/

total 0
drwxr-xr-x  5 blacktop  staff  160 Jan 13 21:39 CFNetwork.framework
drwxr-xr-x  4 blacktop  staff  128 Jan 13 21:39 Combine.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 CoreFoundation.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 CoreServices.framework
drwxr-xr-x  4 blacktop  staff  128 Jan 13 21:39 Foundation.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 IOKit.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 IOSurface.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 MobileCoreServices.framework
drwxr-xr-x  4 blacktop  staff  128 Jan 13 21:39 Network.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 Security.framework
drwxr-xr-x  3 blacktop  staff   96 Jan 13 21:39 SystemConfiguration.framework
```
:::

## `ipsw img4 im4p`

Operations specifically for IM4P (Image4 Payload) files.

### `ipsw img4 im4p info`

Display detailed IM4P information.

```bash
# Display IM4P information
❯ ipsw img4 im4p info kernelcache.im4p

# Output as JSON
❯ ipsw img4 im4p info --json kernelcache.im4p
```

### `ipsw img4 im4p extract`

Extract IM4P data, including decryption and keybag extraction.

### Automatic Key Lookup

The `--lookup` feature can automatically retrieve decryption keys from theapplewiki.com and supports auto-detection from folder structures like `22F76__iPhone11,8/` for various device types including iPhone, iPad, iPod, AppleTV, AudioAccessory, iBridge, and Mac devices.

```bash
# Extract decompressed payload data
❯ ipsw img4 im4p extract kernelcache.im4p

# Extract extra data (if present)
❯ ipsw img4 im4p extract --extra kernelcache.im4p

# Extract keybags as JSON
❯ ipsw img4 im4p extract --kbag encrypted.im4p | jq .

{
  "tag": "sep-firmware.d93.RELEASE.im4p",
  "version": "1",
  "keybags": [
    {
      "type": "prod",
      "iv": "6cfaeef036e382c2fe916172d43aeb6c",
      "key": "9e34c941c4fa95d61f852904f9f7fd1d88021d05fbc4e16eabbe82b6ebd49a79"
    },
    {
      "type": "dev",
      "iv": "912810a723dca6744329a2f0aaedea6b",
      "key": "b154955fe870b603ab3d4d6d673ee329339afb1bcaeab6ea7edacff1e62dc969"
    }
  ]
}

# Decrypt and extract payload
❯ ipsw img4 im4p extract --iv 1234... --key 5678... encrypted.im4p

# Auto-lookup key and decrypt from theapplewiki.com
❯ ipsw img4 im4p extract --lookup --lookup-device iPhone14,2 --lookup-build 20H71 RestoreRamDisk.im4p

# Auto-detect device/build from folder structure (e.g., 22F76__iPhone11,8/...)
❯ ipsw img4 im4p extract --lookup /path/to/22F76__iPhone11,8/sep-firmware.n841.RELEASE.im4p

# Use combined IV+key for decryption (alternative to separate --iv and --key)
❯ ipsw img4 im4p extract --iv-key 1234567890abcdef:5678901234abcdef encrypted.im4p

# Extract to specific output file
❯ ipsw img4 im4p extract --output kernel.bin kernelcache.im4p
```

#### Ever wonder how to mount the RAM disks in the IPSW ?

```bash
❱ ipsw info iPhone17,1_26.0_23A5276f_Restore.ipsw

[IPSW Info]
===========
Version        = 26.0
BuildVersion   = 23A5276f
OS Type        = Development
FileSystem     = 044-45969-087.dmg.aea
SystemOS       = 044-47047-089.dmg.aea
AppOS          = 044-45681-131.dmg
ExclaveOS      = 044-76152-123.dmg.aea
RestoreRamDisk = [044-45855-131.dmg 044-45501-128.dmg]

<SNIP>
```

The RestoreRamDisk DMGs `044-45855-131.dmg` and `044-45501-128.dmg` are the `arm64eCustomerRamDisk` and the `arm64eUpdateRamDisk`, however, you cannot mount them as they are actually **im4p** files. 😕

You can now extract the Img4 payloads with the following command:

```bash
❱ ipsw extract --pattern '044-45855-131.dmg' iPhone17,1_26.0_23A5276f_Restore.ipsw
   • Extracting files matching pattern "044-45855-131.dmg"
      • Created 23A5276f__iPhone17,1/044-45855-131.dmg
      • Created 23A5276f__iPhone17,1/Firmware/044-45855-131.dmg.trustcache
```
```bash
# Extract IM4P payload from IMG4 file
❱ ipsw img4 im4p extract 23A5276f__iPhone17,1/044-45855-131.dmg \
    --output 23A5276f__iPhone17,1/044-45855-131.ramdisk.dmg
      • Extracting Payload        path=23A5276f__iPhone17,1/044-45855-131.ramdisk.dmg
```

And now you can open the 🆕 _DMG_ to mount the RAM disk image.

```bash
❱ open 23A5276f__iPhone17,1/044-45855-131.ramdisk.dmg
```
```bash
❱ ls -l /Volumes/ramdisk/
total 0
drwxr-xr-x   8 blacktop  staff  256 Jun 20 22:05 bin
dr-xr-xr-x   2 blacktop  staff   64 Jun 10 12:35 dev
lrwxr-xr-x   1 blacktop  staff   11 Jun 20 22:05 etc -> private/etc
drwxr-xr-x   3 blacktop  staff   96 Jun 20 22:05 mnt1
drwxr-xr-x   2 blacktop  staff   64 Nov 30  2023 mnt10
drwxr-xr-x   2 blacktop  staff   64 Nov 30  2023 mnt11
drwxr-xr-x   2 blacktop  staff   64 Nov 30  2023 mnt2
drwxr-xr-x   2 blacktop  staff   64 Nov 30  2023 mnt3
drwxr-xr-x   2 blacktop  staff   64 Nov 30  2023 mnt4
drwxr-xr-x   2 blacktop  staff   64 Nov 30  2023 mnt5
drwxr-xr-x   2 blacktop  staff   64 Nov 30  2023 mnt6
drwxr-xr-x   2 blacktop  staff   64 Nov 30  2023 mnt7
drwxr-xr-x   2 blacktop  staff   64 Nov 30  2023 mnt8
drwxr-xr-x   2 blacktop  staff   64 Nov 30  2023 mnt9
drwxr-xr-x   4 blacktop  staff  128 Jun 20 22:05 private
drwxr-xr-x  15 blacktop  staff  480 Jun 20 22:05 sbin
drwxr-xr-x   6 blacktop  staff  192 Jun 20 22:05 System
drwxr-xr-x  10 blacktop  staff  320 Jun 20 22:06 usr
lrwxr-xr-x   1 blacktop  staff   11 Jun 20 22:06 var -> private/var
```

:::info note
This is one of the last places you can find the individual framework dylibs in the IPSW
```bash
❱ ls -l /Volumes/ramdisk/System/Library/Frameworks/
total 0
drwxr-xr-x  5 blacktop  staff  160 Jun 20 22:05 CFNetwork.framework
drwxr-xr-x  4 blacktop  staff  128 Jun 20 22:05 Combine.framework
drwxr-xr-x  3 blacktop  staff   96 Jun 20 22:05 CoreFoundation.framework
drwxr-xr-x  3 blacktop  staff   96 Jun 20 22:05 CoreServices.framework
drwxr-xr-x  4 blacktop  staff  128 Jun 20 22:05 CryptoKit.framework
drwxr-xr-x  3 blacktop  staff   96 Jun 20 22:05 CryptoTokenKit.framework
drwxr-xr-x  4 blacktop  staff  128 Jun 20 22:05 Foundation.framework
drwxr-xr-x  3 blacktop  staff   96 Jun 20 22:05 IOKit.framework
drwxr-xr-x  3 blacktop  staff   96 Jun 20 22:05 IOSurface.framework
drwxr-xr-x  4 blacktop  staff  128 Jun 20 22:05 LocalAuthentication.framework
drwxr-xr-x  3 blacktop  staff   96 Jun 20 22:05 MobileCoreServices.framework
drwxr-xr-x  4 blacktop  staff  128 Jun 20 22:05 Network.framework
drwxr-xr-x  3 blacktop  staff   96 Jun 20 22:05 Security.framework
drwxr-xr-x  3 blacktop  staff   96 Jun 20 22:05 SystemConfiguration.framework
```
:::

### `ipsw img4 im4p create`

Create an IM4P payload from raw data.

```bash
# Create IM4P from kernel with LZSS compression
❯ ipsw img4 im4p create --type krnl --compress lzss kernelcache.bin

# Create IM4P with LZFSE compression for iBoot (macOS only)
❯ ipsw img4 im4p create --type ibot --compress lzfse_iboot iboot.bin

# Create IM4P with version and extra data
❯ ipsw img4 im4p create --type rkrn --version "RestoreKernel" --compress lzss --extra extra.bin kernel.bin

# Create uncompressed IM4P
❯ ipsw img4 im4p create --type logo --compress none logo.png

# Create with custom output path
❯ ipsw img4 im4p create --type dtre --output devicetree.im4p devicetree.bin
```

## `ipsw img4 im4m`

Operations specifically for IM4M (Image4 Manifest) files.

### `ipsw img4 im4m info`

Display IM4M manifest information.

```bash
# Display IM4M manifest information
❯ ipsw img4 im4m info manifest.im4m

# Output as JSON
❯ ipsw img4 im4m info --json manifest.im4m
```

### `ipsw img4 im4m extract`

Extract IM4M manifest from SHSH blob.

```bash
# Extract IM4M from SHSH blob
❯ ipsw img4 im4m extract shsh.blob

# Extract update manifest (if available)
❯ ipsw img4 im4m extract --update shsh.blob

# Extract no-nonce manifest (if available)
❯ ipsw img4 im4m extract --no-nonce shsh.blob

# Extract to specific output file
❯ ipsw img4 im4m extract --output custom.im4m shsh.blob
```

### `ipsw img4 im4m verify`

Verify IM4M manifest against a build manifest.

```bash
# Verify IM4M against build manifest
❯ ipsw img4 im4m verify --build-manifest BuildManifest.plist manifest.im4m

# Strict mode verification (requires all BuildManifest components)
❯ ipsw img4 im4m verify --build-manifest BuildManifest.plist --strict manifest.im4m
```

### `🚧 ipsw img4 person`

Create personalized IMG4 with TSS manifest for device-specific firmware (experimental).

```bash
# Personalize IMG4 with device ECID and nonce (experimental)
❯ ipsw img4 person --ecid 1234567890ABCDEF --nonce FEEDFACE kernel.img4

# Personalize with custom output path
❯ ipsw img4 person --ecid 1234567890ABCDEF --nonce FEEDFACE --output personalized.img4 kernel.img4
```

## `ipsw img4 im4r`

Operations specifically for IM4R (Image4 Restore Info) files.

### `ipsw img4 im4r info`

Display IM4R restore information.

```bash
# Display IM4R restore info from IMG4 file
❯ ipsw img4 im4r info kernel.img4

# Output as JSON
❯ ipsw img4 im4r info --json kernel.img4
```

### `ipsw img4 im4r create`

Create IM4R restore info with a boot nonce.

```bash
# Create IM4R with boot nonce for iOS restore
❯ ipsw img4 im4r create --boot-nonce 1234567890abcdef --output restore.im4r
```
