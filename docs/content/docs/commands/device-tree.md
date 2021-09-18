---
title: "dtree"
date: 2020-01-26T11:02:56-05:00
draft: false
weight: 12
summary: Parse DeviceTrees.
---

### Parse DeviceTrees

Print out SUMMARY

```bash
❯ ipsw download -v 13.3 -d iPhone12,3 pattern DeviceTree
```

```bash
❯ ipsw dtree DeviceTree.d431ap.im4p

      • Product Name: iPhone 11 Pro Max
      • Model: iPhone12,5
      • BoardConfig: D431AP
```

Or print out JSON

```bash
❯ ipsw dtree --json DeviceTree.d431ap.im4p | jq .
```

```json
{
  "device-tree": {
    "#address-cells": 2,
    "#size-cells": 2,
    "AAPL,phandle": 1,
    "children": [
      {
        "chosen": {
          "#address-cells": 2,
          "AAPL,phandle": 2,
   <SNIP>
```

Or remotely

```bash
❯ ipsw dtree --remote https://updates.cdn-apple.com/../iPodtouch_7_13.3_17C54_Restore.ipsw

   • DeviceTree.n112ap.im4p
      • Product Name: iPod touch
      • Model: iPod9,1
      • BoardConfig: N112AP
```
