# 26.5_22F76__vs__26.5.1_22F84

## Inputs

- `iPhone18,1_26.5_22F76_Restore.ipsw`
- `iPhone18,1_26.5.1_22F84_Restore.ipsw`

### Kexts

#### 🆕 NEW (1)

- `com.apple.KEXT.NewKext`

#### ❌ Removed (1)

- `com.apple.KEXT.RemovedKext`

#### ⬆️ Updated (1)

- [/System/Library/Extensions/AppleKEXT.kext/AppleKEXT](KEXTS/System/Library/Extensions/AppleKEXT.kext/AppleKEXT.md)

### KDKs

- [KDK DIFF](KDK.md)

## MachO

### filesystem

#### 🆕 NEW (1)

- `/usr/bin/MACHO_filesystem_new`

#### ❌ Removed (1)

- `/usr/bin/MACHO_filesystem_removed`

#### ⬆️ Updated (1)

- [/usr/bin/MACHO_filesystem_updated](MACHOS/filesystem/usr/bin/MACHO_filesystem_updated.md)

### SystemOS

#### 🆕 NEW (1)

- `/System/Library/MACHO_SystemOS_new`

#### ❌ Removed (1)

- `/System/Library/MACHO_SystemOS_removed`

#### ⬆️ Updated (1)

- [/System/Library/MACHO_SystemOS_updated](MACHOS/SystemOS/System/Library/MACHO_SystemOS_updated.md)

### AppOS

#### 🆕 NEW (1)

- `/System/Library/MACHO_AppOS_new`

#### ❌ Removed (1)

- `/System/Library/MACHO_AppOS_removed`

#### ⬆️ Updated (1)

- [/System/Library/MACHO_AppOS_updated](MACHOS/AppOS/System/Library/MACHO_AppOS_updated.md)

### 🔑 Entitlements

- [Entitlements DIFF](Entitlements.md)

## Sandbox Profiles

### Sandbox Collection (3)

#### 🆕 NEW (1)

- [SANDBOX_collection_new](SANDBOX/Sandbox-Collection/SANDBOX_collection_new.md)

#### ❌ Removed (1)

- [SANDBOX_collection_removed](SANDBOX/Sandbox-Collection/SANDBOX_collection_removed.md)

#### ⬆️ Updated (1)

- [SANDBOX_collection_updated](SANDBOX/Sandbox-Collection/SANDBOX_collection_updated.md)

### Platform Profile (1)

#### ⬆️ Updated (1)

- [SANDBOX_platform_updated](SANDBOX/Platform/SANDBOX_platform_updated.md)

## Firmware

### 🆕 NEW (1)

- `FIRMWARE_new.im4p`

### ❌ Removed (1)

- `FIRMWARE_removed.im4p`

### ⬆️ Updated (1)

- [FIRMWARE_updated.im4p](FIRMWARE/FIRMWARE_updated.im4p.md)

### iBoot

| iOS | Version |
| :-- | :------ |
| 26.5 *(22F76)* | iBoot-IBOOT_old |
| 26.5.1 *(22F84)* | iBoot-IBOOT_new |

#### 🆕 NEW (1)

- [iBoot.IBOOT.section](IBOOT/NEW/iBoot.IBOOT.section.md)

#### ❌ Removed (1)

- [iBoot.IBOOT.section](IBOOT/Removed/iBoot.IBOOT.section.md)

### launchd Config

<details>
  <summary><i>View Updated</i></summary>

```diff
- LAUNCHD old
+ LAUNCHD new
```

</details>

## DSC

### WebKit

| iOS | Version |
| :-- | :------ |
| 26.5 *(22F76)* | Webkit-26.5 |
| 26.5.1 *(22F84)* | Webkit-26.5.1 |

### Dylibs

#### 🆕 NEW (1)

- `/usr/lib/DYLIBS_new.dylib`

#### ❌ Removed (1)

- `/usr/lib/DYLIBS_removed.dylib`

#### ⬆️ Updated (1)

- [/usr/lib/DYLIBS_updated.dylib](DYLIBS/usr/lib/DYLIBS_updated.dylib.md)

## Files

### 🆕 New

#### IPSW (1)

- `/FILES_IPSW_new`

#### filesystem (1)

- `/FILES_filesystem_new`

#### SystemOS (1)

- `/FILES_SystemOS_new`

#### AppOS (1)

- `/FILES_AppOS_new`

### ❌ Removed

#### IPSW (1)

- `/FILES_IPSW_removed`

#### filesystem (1)

- `/FILES_filesystem_removed`

#### SystemOS (1)

- `/FILES_SystemOS_removed`

#### AppOS (1)

- `/FILES_AppOS_removed`

## Localizations

### filesystem

#### 🆕 NEW (1)

<details>
  <summary><i>View New</i></summary>

##### Localizable

>  `/Localizations_filesystem_new.lproj/Localizable.strings`

```text
LOC filesystem new content
```

</details>

#### ❌ Removed (1)

- `/Localizations_filesystem_removed.lproj/Localizable.strings`

#### ⬆️ Updated (1)

- [/Localizations_filesystem_updated.lproj/Localizable.strings](LOCALIZATIONS/filesystem/Localizations_filesystem_updated.lproj/Localizable.strings.md)

### SystemOS

#### 🆕 NEW (1)

<details>
  <summary><i>View New</i></summary>

##### Localizable

>  `/Localizations_SystemOS_new.lproj/Localizable.strings`

```text
LOC SystemOS new content
```

</details>

#### ❌ Removed (1)

- `/Localizations_SystemOS_removed.lproj/Localizable.strings`

#### ⬆️ Updated (1)

- [/Localizations_SystemOS_updated.lproj/Localizable.strings](LOCALIZATIONS/SystemOS/Localizations_SystemOS_updated.lproj/Localizable.strings.md)

### AppOS

#### 🆕 NEW (1)

<details>
  <summary><i>View New</i></summary>

##### Localizable

>  `/Localizations_AppOS_new.lproj/Localizable.strings`

```text
LOC AppOS new content
```

</details>

#### ❌ Removed (1)

- `/Localizations_AppOS_removed.lproj/Localizable.strings`

#### ⬆️ Updated (1)

- [/Localizations_AppOS_updated.lproj/Localizable.strings](LOCALIZATIONS/AppOS/Localizations_AppOS_updated.lproj/Localizable.strings.md)

## Feature Flags

### filesystem

#### 🆕 NEW (1)

<details>
  <summary><i>View New</i></summary>

##### FeatureFlags_filesystem_new.plist

>  `/FeatureFlags_filesystem_new.plist`

```xml
<plist>FEATURES filesystem new</plist>
```

</details>

#### ❌ Removed (1)

- `/FeatureFlags_filesystem_removed.plist`

#### ⬆️ Updated (1)

- [/FeatureFlags_filesystem_updated.plist](FEATURES/filesystem/FeatureFlags_filesystem_updated.plist.md)

### SystemOS

#### 🆕 NEW (1)

<details>
  <summary><i>View New</i></summary>

##### FeatureFlags_SystemOS_new.plist

>  `/FeatureFlags_SystemOS_new.plist`

```xml
<plist>FEATURES SystemOS new</plist>
```

</details>

#### ❌ Removed (1)

- `/FeatureFlags_SystemOS_removed.plist`

#### ⬆️ Updated (1)

- [/FeatureFlags_SystemOS_updated.plist](FEATURES/SystemOS/FeatureFlags_SystemOS_updated.plist.md)

### AppOS

#### 🆕 NEW (1)

<details>
  <summary><i>View New</i></summary>

##### FeatureFlags_AppOS_new.plist

>  `/FeatureFlags_AppOS_new.plist`

```xml
<plist>FEATURES AppOS new</plist>
```

</details>

#### ❌ Removed (1)

- `/FeatureFlags_AppOS_removed.plist`

#### ⬆️ Updated (1)

- [/FeatureFlags_AppOS_updated.plist](FEATURES/AppOS/FeatureFlags_AppOS_updated.plist.md)

## EOF
