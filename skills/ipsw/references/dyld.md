# dyld_shared_cache (DSC) Analysis

## Contents
- [Get a DSC](#get-a-dsc)
- [List and resolve dylibs](#list-and-resolve-dylibs)
- [Addresses and symbols](#addresses-and-symbols)
- [Disassembly](#disassembly)
- [The .a2s symbol cache](#the-a2s-symbol-cache)
- [Cross-references](#cross-references)
- [Who uses what: imports, soft links, search](#who-uses-what-imports-soft-links-search)
- [ObjC and Swift optimization data](#objc-and-swift-optimization-data)
- [Extract dylibs](#extract-dylibs)
- [Compare two caches](#compare-two-caches)
- [Other cache data](#other-cache-data)

## Get a DSC

```bash
# From an IPSW (local path or, with --remote, a URL)
ipsw extract --dyld --dyld-arch arm64e -o ./extracted/ "$IPSW"

# The host Mac's cache (macOS 13 and later)
DSC=/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
```

Modern caches are split: `dyld_shared_cache_arm64e` is the main file and dozens of subcaches
(`.01`, `.02`, …, `.dylddata`, `.dyldlinkedit`, `.symbols`) sit beside it. Always pass the main
file and keep the whole set together when copying. Without `--dyld-arch`, `extract --dyld` pulls
every architecture in the image (for example x86_64 and Rosetta caches from a macOS IPSW).

## List and resolve dylibs

```bash
ipsw dyld info "$DSC"                                   # header, mappings, platform, UUID
ipsw dyld info --dylibs --json "$DSC" | jq -r '.dylibs[].name'
ipsw dyld webkit --json "$DSC" | jq -r .version         # WebKit version (offline)
```

Many commands take a `<DYLIB>` argument. A short name that matches more than one image (`UIKit`,
`SwiftUI`, `SpringBoard`) opens an interactive picker, which fails without a terminal. Resolve
the full install path with the `jq` line above and pass that.

## Addresses and symbols

```bash
ipsw dyld a2s "$DSC" 0x18ebfa9c8                 # address → nearest symbol + offset (no cache needed)
ipsw dyld symaddr "$DSC" _malloc --image libsystem_malloc.dylib   # exact symbol name → address
ipsw dyld a2o "$DSC" 0x18ebfa9c8                 # address → file offset
ipsw dyld o2a "$DSC" 0xebfa9c8                   # file offset → address
ipsw dyld dump "$DSC" 0x18ebfa9c8 --size 64      # raw bytes (--addr prints uint64s)
```

`symaddr` matches **exact** names; `--all` prints every exact match instead of stopping at the
first. ObjC methods are symbols too; an instance method starts with `-`, so pass it after `--`:

```bash
ipsw dyld symaddr "$DSC" --image /System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore \
  -- '-[UIApplication endBackgroundTask:]'
# 0x18928709c:	(local|__TEXT.__text)	-[UIApplication endBackgroundTask:]	UIKitCore
```

For regular expressions, use a JSON batch file:

```bash
cat > lookups.json <<'EOF'
[{"pattern": "_NS.*Error", "image": "Foundation"},
 {"pattern": "_objc_msgSend", "image": "libobjc.A.dylib"}]
EOF
ipsw dyld symaddr "$DSC" --in lookups.json --output results.json
```

`dyld a2f` resolves the containing function with its start and end; batch mode reads addresses
from a file or stdin and prints JSON (addresses in decimal):

```bash
ipsw dyld a2f "$DSC" 0x18ebfa9c8
# 0x18ebfa9c8: _find_registered_zone + 12 (start: 0x18ebfa9bc, end: 0x18ebfab28)
echo 0x18ec25340 | ipsw dyld a2f "$DSC" --in /dev/stdin
# [{"addr":6690067264,"start":6690067248,"end":6690067284,"size":36,"name":"_aligned_alloc",...}]
```

## Disassembly

```bash
ipsw dyld disass "$DSC" --vaddr 0x18ebfa9a8 --count 40
ipsw dyld disass "$DSC" --symbol _malloc --symbol-image libsystem_malloc.dylib
ipsw dyld disass "$DSC" --vaddr 0x18ebfa9a8 --json      # machine-readable
ipsw dyld disass "$DSC" --vaddr 0x18ebfa9a8 --quiet     # skip analysis markup: fastest
```

- `--symbol` is an exact name. `--symbol-image` narrows the symbol search; `--image` means
  "disassemble these whole dylibs" and is ignored when `--symbol` is set.
- `--demangle` demangles Swift names in the listing.
- `--dec --dec-llm <provider>` sends the function to an LLM for decompilation (needs that
  provider's API key; see `ipsw dyld disass --help`).

## The .a2s symbol cache

The first `disass` (except `--quiet --vaddr`), `xref`, `extract --stubs`, `stubs`, `slide`, or
`prewarm` on a cache builds `<DSC>.a2s`: a one-time pass that takes minutes and writes roughly
1.5 GB for a current iOS cache. Later runs reuse it. If the DSC's directory is read-only, the
cache goes to `$TMPDIR/<UUID>.a2s`; pass `--cache <file>` to choose the location. `a2s` and
`symaddr` never need it.

## Cross-references

`dyld xref` is marked 🚧 (work in progress) in `--help`.

```bash
ipsw dyld xref "$DSC" 0x18ebfa9a8              # searches only the dylib containing the address
ipsw dyld xref "$DSC" 0x18ebfa9a8 --imports    # plus every dylib that imports that dylib
ipsw dyld xref "$DSC" 0x18ebfa9a8 --image /System/Library/Frameworks/Foundation.framework/Foundation
```

`--all` disassembles every image in the cache; on a full iOS cache that is very slow. Start with
the default, then `--imports`.

## Who uses what: imports, soft links, search

```bash
# Dylibs, and filesystem apps/daemons from the launch closures, that load a given dylib
ipsw dyld imports "$DSC" /System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices

# Bind symbols a dylib imports (forward dependencies); --filter takes a regex
ipsw dyld imports "$DSC" --image /System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices

# SOFT_LINK globals: symbols a dylib resolves lazily at runtime (tsv or --format jsonl)
ipsw dyld softlinks "$DSC" --image /System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices

# Search every dylib's load commands, imports, sections, or UUID (regexes)
ipsw dyld search "$DSC" --import 'SpringBoardServices'
ipsw dyld search "$DSC" --section '__AUTH_CONST.__auth_ptr'     # arm64e authenticated pointers
ipsw dyld search "$DSC" --section '^__TPRO_CONST'               # read-only-after-init data
ipsw dyld search "$DSC" --uuid <UUID>

# ObjC / Swift metadata search across the cache (~20s)
ipsw dyld search objc "$DSC" --class '^UIApplication$'
ipsw dyld search swift "$DSC" --protocol 'Widget'
```

## ObjC and Swift optimization data

```bash
ipsw dyld objc --class "$DSC"      # every class in the ObjC optimization tables (also --proto, --sel, --imp-cache)
ipsw dyld swift "$DSC" --types --demangle   # Swift conformance tables (or --metadata, --foreign)
```

For readable interfaces, use `class-dump` / `swift-dump` (see `class-dump.md`).

## Extract dylibs

```bash
ipsw dyld extract "$DSC" /System/Library/Frameworks/Security.framework/Security -o ./dylibs/ --objc --stubs
ipsw dyld extract "$DSC" --all -o ./dylibs/                   # every dylib (large)
ipsw dyld tbd "$DSC" /System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices -o ./tbd/
ipsw dyld split "$DSC" --output ./split/                      # macOS only; uses Xcode's dsc_extractor
```

`--objc` and `--stubs` add ObjC and stub-island names to the extracted symtab, which helps
external disassemblers. `tbd` writes a text stub so you can link against a private framework.

## Compare two caches

```bash
ipsw dyld info --dylibs --delta "$OLD_DSC" "$NEW_DSC"          # markdown: new/removed dylibs and version changes
ipsw dyld info --dylibs --delta --json "$OLD_DSC" "$NEW_DSC" \
  | jq '{added: (.added|length), removed: (.removed|length), changed: (.changed|length)}'
ipsw dyld webkit --diff --json "$OLD_DSC" "$NEW_DSC"            # {"old":…,"new":…,"changed":true}
```

`--diff` and `--delta` are mutually exclusive and both need `--dylibs`; with `--json` they emit
sorted `added`, `removed`, and `changed` lists. For per-dylib ObjC and Swift API changes, use
`class-dump --diff` / `swift-dump --diff` (see `class-dump.md`).

## Other cache data

| Command | Shows |
|---------|-------|
| `dyld image "$DSC" --no-color` | every on-device app and daemon dyld prebuilt a loader for (thousands of paths, no mount needed) |
| `dyld image "$DSC" /usr/libexec/securityd --no-color` | one executable's loader: CDHash, code-signature offsets, loader flags |
| `dyld patches "$DSC" --image libsystem_malloc.dylib --sym _malloc` | which dylibs patch (interpose) an export |
| `dyld stubs "$DSC"` | stub islands |
| `dyld slide "$DSC"` | slide (rebase) info |
| `dyld prewarm "$DSC"` | prewarming data |
| `dyld macho "$DSC" <DYLIB> --loads` | load commands of an in-cache dylib (also `--objc`, `--swift`, `--starts`, `--strings`, `--symbols`) |
| `dyld str "$DSC" "needle" ["needle2" …]` | fast byte search for literal strings across the whole cache; `--pattern REGEX` is slow; there is no per-image filter |
