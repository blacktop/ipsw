# Gadget Search

> Search for byte patterns *(gadgets)* in DSC dylibs

```bash
❯ ipsw dyld macho 20A5339d__iPhone14,2/dyld_shared_cache_arm64e JavaScriptCore \
                  --search "7f 23 03 d5 * * * * f6 57 01 a9"

Search Results
--------------
"0x199f25c80"
0x199f26804
0x199f285c4
"0x199f286c4"
0x199f28860
0x199f289d8
0x199f2966c
```

```bash
❯ ipsw dyld disass 20A5339d__iPhone14,2/dyld_shared_cache_arm64e -a "0x199f25c80" -c 3 --quiet
```

```armasm
sub_199f25c80:
0x199f25c80:  7f 23 03 d5       pacibsp
0x199f25c84:  ff 03 01 d1       sub     sp, sp, #0x40
0x199f25c88:  f6 57 01 a9       stp     x22, x21, [sp, #0x10]
```

```bash
❯ ipsw dyld disass 20A5339d__iPhone14,2/dyld_shared_cache_arm64e -a "0x199f286c4" -c 3 --quiet
```

```armasm
sub_199f286c4:
0x199f286c4:  7f 23 03 d5       pacibsp
0x199f286c8:  f8 5f bc a9       stp     x24, x23, [sp, #-0x40]!
0x199f286cc:  f6 57 01 a9       stp     x22, x21, [sp, #0x10]
```
