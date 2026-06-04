# 26.5_22F76__vs__26.5.1_22F84

## Inputs

- `iPhone18,1_26.5_22F76_Restore.ipsw`
- `iPhone18,1_26.5.1_22F84_Restore.ipsw`

### Kexts

#### 🆕 NEW (1)

- `com.apple.KEXT.NewKext`

#### ❌ Removed (1)

- `com.apple.KEXT.RemovedKext`

### ⬆️ Updated (1)

<details>
  <summary><i>View Updated</i></summary>

#### AppleKEXT

>  `/System/Library/Extensions/AppleKEXT.kext/AppleKEXT`

```diff
- KEXT old line
+ KEXT new line
```

</details>

### KDKs

- [KDK DIFF](KDK.md)

## MachO

### filesystem

#### 🆕 NEW (1)

- `/usr/bin/MACHO_filesystem_new`

#### ❌ Removed (1)

- `/usr/bin/MACHO_filesystem_removed`

#### ⬆️ Updated (1)

<details>
  <summary><i>View Updated</i></summary>

##### MACHO_filesystem_updated

>  `/usr/bin/MACHO_filesystem_updated`

```diff
- MACHO filesystem old
+ MACHO filesystem new
```

</details>

### SystemOS

#### 🆕 NEW (1)

- `/System/Library/MACHO_SystemOS_new`

#### ❌ Removed (1)

- `/System/Library/MACHO_SystemOS_removed`

#### ⬆️ Updated (1)

<details>
  <summary><i>View Updated</i></summary>

##### MACHO_SystemOS_updated

>  `/System/Library/MACHO_SystemOS_updated`

```diff
- MACHO SystemOS old
+ MACHO SystemOS new
```

</details>

### AppOS

#### 🆕 NEW (1)

- `/System/Library/MACHO_AppOS_new`

#### ❌ Removed (1)

- `/System/Library/MACHO_AppOS_removed`

#### ⬆️ Updated (1)

<details>
  <summary><i>View Updated</i></summary>

##### MACHO_AppOS_updated

>  `/System/Library/MACHO_AppOS_updated`

```diff
- MACHO AppOS old
+ MACHO AppOS new
```

</details>

### 🔑 Entitlements

- [Entitlements DIFF](Entitlements.md)

### Sandbox Profiles

- [Sandbox Profiles DIFF](Sandbox.md)

## Firmware

### 🆕 NEW (1)

- `FIRMWARE_new.im4p`

### ❌ Removed (1)

- `FIRMWARE_removed.im4p`

### ⬆️ Updated (1)

<details>
  <summary><i>View Updated</i></summary>

#### FIRMWARE_updated.im4p

>  `FIRMWARE_updated.im4p`

```diff
- FIRMWARE old
+ FIRMWARE new
```

</details>

### iBoot

| iOS | Version |
| :-- | :------ |
| 26.5 *(22F76)* | iBoot-IBOOT_old |
| 26.5.1 *(22F84)* | iBoot-IBOOT_new |

#### 🆕 NEW (1)

<details>
  <summary><i>View NEW</i></summary>

##### `iBoot.IBOOT.section`
  - `IBOOT new string one of sufficient length`

</details>

#### ❌ Removed (1)

<details>
  <summary><i>View Removed</i></summary>

##### `iBoot.IBOOT.section`
  - `IBOOT removed string one of sufficient length`

</details>

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

<details>
  <summary><i>View Updated</i></summary>

#### DYLIBS_updated.dylib

>  `/usr/lib/DYLIBS_updated.dylib`

```diff
- DYLIBS old
+ DYLIBS new
```

</details>

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

<details>
  <summary><i>View Updated</i></summary>

##### Localizable

>  `/Localizations_filesystem_updated.lproj/Localizable.strings`

```diff
- LOC filesystem old
+ LOC filesystem new
```


</details>

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

<details>
  <summary><i>View Updated</i></summary>

##### Localizable

>  `/Localizations_SystemOS_updated.lproj/Localizable.strings`

```diff
- LOC SystemOS old
+ LOC SystemOS new
```


</details>

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

<details>
  <summary><i>View Updated</i></summary>

##### Localizable

>  `/Localizations_AppOS_updated.lproj/Localizable.strings`

```diff
- LOC AppOS old
+ LOC AppOS new
```


</details>

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

<details>
  <summary><i>View Updated</i></summary>

##### FeatureFlags_filesystem_updated.plist

>  `/FeatureFlags_filesystem_updated.plist`

```diff
- FEATURES filesystem old
+ FEATURES filesystem new
```


</details>

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

<details>
  <summary><i>View Updated</i></summary>

##### FeatureFlags_SystemOS_updated.plist

>  `/FeatureFlags_SystemOS_updated.plist`

```diff
- FEATURES SystemOS old
+ FEATURES SystemOS new
```


</details>

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

<details>
  <summary><i>View Updated</i></summary>

##### FeatureFlags_AppOS_updated.plist

>  `/FeatureFlags_AppOS_updated.plist`

```diff
- FEATURES AppOS old
+ FEATURES AppOS new
```


</details>

## EOF
