---
title: "ent"
date: 2021-04-14T14:14:22-04:00
draft: false
weight: 30
summary: Search IPSW filesystem DMG for MachOs with a given entitlement.
---

Search IPSW filesystem DMG for MachOs with a given entitlement `<true/>`

```bash
$ ipsw ent iPhone11,8,iPhone12,1_14.5_18E5199a_Restore.ipsw --ent platform-application
   • Found ipsw entitlement database file...
   • Files containing entitlement: platform-application

platform-application /System/Library/PrivateFrameworks/MobileAccessoryUpdater.framework/XPCServices/EAUpdaterService.xpc/EAUpdaterService
platform-application /private/var/staged_system_apps/Home.app/Home
platform-application /usr/libexec/morphunassetsupdaterd
platform-application /System/Library/Frameworks/CryptoTokenKit.framework/PlugIns/setoken.appex/setoken
platform-application /usr/libexec/swcd
<SNIP>
```
