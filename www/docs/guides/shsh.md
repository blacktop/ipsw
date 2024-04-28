---
description: Dumping shsh blobs allows you to downgrade iOS later.
---

# Dump SHSH Blobs

> Dumping shsh blobs allows you to downgrade iOS later.

[Jailbreak](https://checkra.in/) your iDevice and install openssh

```bash
❯ ipsw idev proxy --lport 2222 --rport 22
   • Connecting proxy to device lport=2222 rport=22
```

```bash
❯ ipsw ssh shsh

   • Connecting to root@localhost:2222
      • Parsing shsh
      • Parsing IMG4
         • Dumped SHSH blob to 1249767383957670.dumped.shsh
```
