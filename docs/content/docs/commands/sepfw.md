---
title: "sepfw"
date: 2021-06-03T23:14:17-06:00
draft: false
weight: 17
summary: Dump sep-firmware MachOs.
---

### Dump sep-firmware MachOs

```bash
$ ipsw sepfw sep-firmware.d53p.RELEASE.im4p.dec

   • DUMPING: kernel, SEPOS and 14 Apps
      • Dumping kernel            offset=0x4000 uuid=CECFDD94-2E4F-3118-9EC3-C3933F0DE2CA
      • Dumping SEPOS             offset=0x564000 uuid=FF2C31BE-DED5-35DA-8619-BFF27234B26A
      • Dumping SEPD              offset=0x2a4000-0x2b8000 uuid=75159F79-BA1A-3550-8016-1AC5FF7D9257
      • Dumping AESSEP            offset=0x2b8000-0x2c4000 uuid=B0BC153A-B351-369F-9B36-A8455216114F
      • Dumping dxio              offset=0x2c4000-0x2d0000 uuid=34C40942-4077-3C4F-9EF5-06FF1364CF0F
      • Dumping entitlement       offset=0x2d0000-0x2e8000 uuid=AD029F43-02FA-340B-9ADA-3A179706518E
      • Dumping skg               offset=0x2e8000-0x2f8000 uuid=49E2B275-9182-3459-87F3-F622EE4816DC
      • Dumping sars              offset=0x2f8000-0x31c000 uuid=F61FA097-212F-363D-A82E-96EF73CAC6CD
      • Dumping ARTM              offset=0x31c000-0x324000 uuid=62B3072F-52E4-32FF-8D4A-CF2FB15F9575
      • Dumping xART              offset=0x324000-0x334000 uuid=8DE03D03-9EF0-31F1-93D0-F686C5CBB93C
      • Dumping eispAppl_d5x      offset=0x334000-0x3cc000 uuid=519872B2-8A6F-34B6-AD82-2A120ED5C42B
      • Dumping scrd              offset=0x3cc000-0x3e8000 uuid=4D033F31-23C4-3959-B002-836AF5776E83
      • Dumping pass_ocelot       offset=0x3e8000-0x3f0000 uuid=0A91FBC3-EBC3-35BD-B7E3-005AE9E2D94B
      • Dumping sks               offset=0x3f0000-0x494000 uuid=19673D6F-A2A5-3696-9007-DC8C6FC6DD79
      • Dumping sprl_d5x          offset=0x494000-0x528000 uuid=BEA0B3EB-1BA3-38D5-83D0-B1B52E28A52B
      • Dumping sse_r1            offset=0x528000-0x564000 uuid=B1096477-879C-3E41-9057-F486FE3EC0EB

```

> **NOTE:** This was tested on an iPhone12,1 (A14) running iOS14.5beta7 _(most likely won't work on older versions)_
