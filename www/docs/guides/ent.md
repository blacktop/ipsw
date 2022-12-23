---
hide_table_of_contents: true
description: Querying the IPSWs for files containing a specific entitlement
---

# Parse Entitlements

### Search IPSW filesystem DMG for MachOs with a given **entitlement** `<true/>`

```bash
❯ ipsw ent iPhone11,8,iPhone12,1_14.5_18E5199a_Restore.ipsw --ent platform-application
   • Found ipsw entitlement database file...
   • Files containing entitlement: platform-application

platform-application /System/Library/PrivateFrameworks/MobileAccessoryUpdater.framework/XPCServices/EAUpdaterService.xpc/EAUpdaterService
platform-application /private/var/staged_system_apps/Home.app/Home
platform-application /usr/libexec/morphunassetsupdaterd
platform-application /System/Library/Frameworks/CryptoTokenKit.framework/PlugIns/setoken.appex/setoken
platform-application /usr/libexec/swcd
<SNIP>
```

### Search IPSW filesystem DMG for MachOs with a given **file name** and dump it's entitlements

```bash
❯ ipsw ent iPhone11,8,iPhone12,1_14.5_18E5199a_Restore.ipsw --file WebContent
   • Found ipsw entitlement database file...
   • /Applications/WebContentAnalysisUI.app/WebContentAnalysisUI

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.UIKit.vends-view-services</key>
	<true/>
	<key>com.apple.private.screen-time</key>
	<true/>
	<key>com.apple.private.security.container-required</key>
	<true/>
	<key>com.apple.security.exception.shared-preference.read-only</key>
	<array>
		<string>com.apple.springboard</string>
	</array>
	<key>keychain-access-groups</key>
	<array>
		<string>apple</string>
		<string>com.apple.preferences</string>
	</array>
</dict>
</plist>

   • /System/Library/Frameworks/WebKit.framework/XPCServices/com.apple.WebKit.WebContent.xpc/com.apple.WebKit.WebContent

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.QuartzCore.secure-mode</key>
	<true/>
	<key>com.apple.QuartzCore.webkit-end-points</key>
	<true/>
	<key>com.apple.mediaremote.set-playback-state</key>
	<true/>
	<key>com.apple.pac.shared_region_id</key>
	<string>WebContent</string>
	<key>com.apple.private.allow-explicit-graphics-priority</key>
	<true/>
	<key>com.apple.private.coremedia.extensions.audiorecording.allow</key>
	<true/>
	<key>com.apple.private.coremedia.pidinheritance.allow</key>
	<true/>
	<key>com.apple.private.memorystatus</key>
	<true/>
	<key>com.apple.private.network.socket-delegate</key>
	<true/>
	<key>com.apple.private.pac.exception</key>
	<true/>
	<key>com.apple.private.security.message-filter</key>
	<true/>
	<key>com.apple.private.webinspector.allow-remote-inspection</key>
	<true/>
	<key>com.apple.private.webinspector.proxy-application</key>
	<true/>
	<key>com.apple.private.webkit.use-xpc-endpoint</key>
	<true/>
	<key>com.apple.runningboard.assertions.webkit</key>
	<true/>
	<key>com.apple.tcc.delegated-services</key>
	<array>
		<string>kTCCServiceCamera</string>
		<string>kTCCServiceMicrophone</string>
	</array>
	<key>dynamic-codesigning</key>
	<true/>
	<key>seatbelt-profiles</key>
	<array>
		<string>com.apple.WebKit.WebContent</string>
	</array>
</dict>
</plist>
```

Use a previously created entitlements database

```bash
❯ ipsw ent iPhone11,8,iPhone12,1_14.5_18E5199a_Restore.ipsw --ent platform-application --db /tmp/IPSW.entDB
```

> **NOTE:** When you run the `ipsw ent` command on an **IPSW** it will auto-create **IPSW.entDB** next to the **IPSW** file and it will try and use that if you run it again on the same **IPSW**.

### Diff two IPSWs

```bash
❯ ipsw ent --diff test-caches/IPSWs/iPhone15,2_16.1_20B5050f_Restore.ipsw test-caches/IPSWs/iPhone15,2_16.1_20B5056e_Restore.ipsw
```
