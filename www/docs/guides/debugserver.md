---
description: Prep jailbroken device for remote debugging.
---

# Prep device for remote debugging

> This adds more powerful entitlements to the debugserver, improves logging and symbolication of crashes.

[Jailbreak](https://checkra.in/) your iDevice and install openssh

```bash
❯ ipsw idev proxy --lport 2222 --rport 22
   • Connecting proxy to device lport=2222 rport=22
```

```bash
❯ ipsw ssh debugserver --force

   • Connecting to root@localhost:2222
? Select the DeveloperDiskImage you want to extract the debugserver from: 14.1/DeveloperDiskImage.dmg
      • Mounting DeveloperDiskImage
      • Adding entitlements to /usr/bin/debugserver
      • Copying /usr/bin/debugserver to device
      • Enabling private data in logs
      • Enabling symbolication of mobile crash logs
      • Restarting logd
      • Unmounting DeveloperDiskImage
```
