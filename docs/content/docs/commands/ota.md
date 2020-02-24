---
title: "ota"
date: 2020-02-23T21:07:22-05:00
draft: false
weight: 100
summary: Parse OTA zip files.
---

### List files in OTA

```bash
$ ipsw ota -l OTA.zip

-rw-r--r-- uid=0 gid=0 10 MB  System/Library/Frameworks/ARKit.framework/MLModels/H12/PersonSegmentation_H12.mlmodelc/model.espresso.hwx
-rw-r--r-- uid=0 gid=0 21 MB  System/Library/Frameworks/ARKit.framework/MLModels/H12/SemanticSegmentation_H12.mlmodelc/model.espresso.hwx
-rw-r--r-- uid=0 gid=0 12 MB  System/Library/Frameworks/ARKit.framework/gan_model.mlmodelc/model.espresso.weights
-rw-r--r-- uid=0 gid=0 17 MB  System/Library/Frameworks/MetalPerformanceShaders.framework/Frameworks/MPSNeuralNetwork.framework/default.metallib
-rw-r--r-- uid=0 gid=0 9.4 MB System/Library/Frameworks/Vision.framework/gazeflow-mcbdnde3m8_225900_opt_quantized_w_conv_u16_fc_fp16.espresso.weights
-rw-r--r-- uid=0 gid=0 9.4 MB System/Library/Frameworks/Vision.framework/pumtc2j5f7_wide_u8.espresso.weights
-rw-r--r-- uid=0 gid=0 11 MB  System/Library/Frameworks/Vision.framework/scene-classifier.bin
-rw-r--r-- uid=0 gid=0 16 MB  System/Library/LinguisticData/RequiredAssets_de.bundle/AssetData/de.lm/montreal.dat
-rw-r--r-- uid=0 gid=0 14 MB  System/Library/LinguisticData/RequiredAssets_en.bundle/AssetData/en.lm/montreal.dat
-rw-r--r-- uid=0 gid=0 17 MB  System/Library/LinguisticData/RequiredAssets_es.bundle/AssetData/es.lm/montreal.dat
<SNIP>
```

### Extract file(s)

```bash
$ ipsw ota OTA.zip dyld_shared_cache
   • Extracting -rwxr-xr-x uid=0, gid=80, 1.7 GB, System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e
```

**NOTE:** you can supply a pattern/substring to match
