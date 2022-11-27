---
hide_table_of_contents: true
description: How to use lookup JSON files
---

# Lookup DSC Symbols

> How to use lookup JSON files.

```bash
❯ jq . sym_lookup.json
```
```json
[
  {
    "regex": ".*zero.*",
    "image": "libsystem_c.dylib"
  }
]
```

```bash
❯ ipsw dyld symaddr dyld_shared_cache_arm64e --in sym_lookup.json | jq .
```
```json
[
  {
    "name": "__utmpx_working_copy.idzero",
    "image": "/usr/lib/system/libsystem_c.dylib",
    "type": "__DATA.__bss",
    "address": 7903949176
  },
<SNIP>
  {
    "name": "_zeroes",
    "image": "/usr/lib/system/libsystem_c.dylib",
    "type": "__DATA.__data",
    "address": 7903945364
  },
  {
    "name": "__platform_bzero",
    "image": "libsystem_c.dylib",
    "type": "ext|undef"
  },
  {
    "name": "_bzero",
    "image": "libsystem_c.dylib",
    "type": "__platform_bzero re-exported from libsystem_platform.dylib",
    "address": 8345742624
  }
]
```