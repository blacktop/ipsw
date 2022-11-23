# Stub Islands

> iOS16 added a NEW concept to dyld4 and the `dyld_shared_cache` sub-caches called **Stub Islands**.  

### We've introduced a `ipsw dyld stubs` command to dump them all out and the symbol they *stub* to

```bash
❯ ipsw dyld stubs 20B5050f__iPhone15,2/dyld_shared_cache_arm64e | head
   • Loading symbol cache file...
0x199ce7640: _CMPhotoJPEGWriteMPFWithJPEG
0x1ad5d5970: _objc_autorelease
0x1c8d0f350: _$ss10_HashTableV12previousHole6beforeAB6BucketVAF_tF
0x1cf7eba00: _$s5TeaUI14KeyCommandItemVMa
0x1bb1f8a40: _swift_task_switch
0x1c1f5edc0: _$s4GRDB3RowC19fastDecodeIfPresent_16atUncheckedIndexxSgxm_SitKAA24DatabaseValueConvertibleRzAA015StatementColumnL0RzlF
0x1ec2127d0: _CGColorGetColorSpace
0x207434db0: __swift_stdlib_strtod_clocale
0x1a0622e00: _objc_retain_x20
0x1c1f87d30: _swift_getTupleTypeLayout3
"0x1bb220d70: _fcntl"
```

### Disassemble the *stub*

```bash
❯ ipsw dyld disass 20B5050f__iPhone15,2/dyld_shared_cache_arm64e -a "0x1bb220d70" --count 5
   • Loading symbol cache file...
```

```armasm
j__fcntl
0x1bb220d70:  30 7b 04 b0   adrp     x16, 0x1c4185000
0x1bb220d74:  10 32 1b 91   add      x16, x16, #0x6cc ; _fcntl
0x1bb220d78:  00 02 1f d6   br       x16
0x1bb220d7c:  20 00 20 d4   brk      #0x1
```

### Lookup the address

```bash
❯ ipsw dyld a2s 20B5050f__iPhone15,2/dyld_shared_cache_arm64e "0x1bb220d70" --mapping --image
   • Loading symbol cache file...
```

MAPPING
-------
  > STUB Island *(dsc.18)* UUID: `7623C890-8F05-3DFD-AADF-CE765217C572`

| SEG          | INITPROT | MAXPROT | SIZE                | ADDRESS     | FILE OFFSET | SLIDE INFO OFFSET | FLAGS |
| ------------ | -------- | ------- | ------------------- | ----------- | ----------- | ----------------- | ----- |
| __TEXT_STUBS | r-x      | r-x     | 0x00080000 (524 kB) | 0x1bb1b4000 | 0x00000000  | 0x00000000        | 8     |
   
```bash
   ⨯ address 0x1bb220d70 not in any dylib

0x1bb220d70: "j__fcntl"
```

### Locate any `xrefs`

```bash
❯ ipsw dyld xref 20B5050f__iPhone15,2/dyld_shared_cache_arm64e 0x1bb220d70 --all
   • Loading symbol cache file...
   • No XREFS found            dylib=/usr/lib/libobjc.A.dylib sym=j__fcntl xrefs=0
   <SNIP>
   • XREFS                     dylib=/System/Library/PrivateFrameworks/CloudKitDaemon.framework/CloudKitDaemon sym=j__fcntl xrefs=1
0x1b9f577ec: "openFdForDownloadPath:error: + 128"   
```