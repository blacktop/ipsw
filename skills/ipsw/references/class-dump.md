# ObjC and Swift Header Dumping

`ipsw class-dump` (ObjC) and `ipsw swift-dump` (Swift) read metadata from a dylib inside a
dyld_shared_cache (DSC) or from a standalone Mach-O. Both can also diff a dylib between two
releases.

## Contents
- [Name the dylib by install path](#name-the-dylib-by-install-path)
- [Dump ObjC](#dump-objc)
- [Filter and annotate](#filter-and-annotate)
- [Write header files](#write-header-files)
- [Find which dylib defines a class](#find-which-dylib-defines-a-class)
- [Swift](#swift)
- [Diff a dylib between releases](#diff-a-dylib-between-releases)
- [Standalone Mach-Os](#standalone-mach-os)

Examples assume `DSC` points at a `dyld_shared_cache_arm64e` (see `dyld.md` for where to get one).

## Name the dylib by install path

A short name such as `UIKit`, `SwiftUI`, or `SpringBoard` often matches more than one image
(the framework plus an accessibility bundle). ipsw then opens an interactive picker, which fails
when there is no terminal. Pass the full install path instead, and look it up first:

```bash
ipsw dyld info --dylibs --json "$DSC" | jq -r '.dylibs[].name' | grep -i springboard
```

Several public framework names are thin shims. UIKit's classes live in
`/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore`; dumping `UIKit.framework/UIKit`
prints `no ObjC data found`.

## Dump ObjC

```bash
# One dylib
ipsw class-dump "$DSC" /System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices

# Every dylib in the cache (large; write to files, see below)
ipsw class-dump "$DSC" --all --headers -o ./headers/
```

## Filter and annotate

`--class`, `--proto`, and `--cat` take regular expressions.

```bash
ipsw class-dump "$DSC" /System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore --class '^UIApplication$'
ipsw class-dump "$DSC" /System/Library/Frameworks/Security.framework/Security --class '.*Trust.*'
ipsw class-dump "$DSC" /System/Library/Frameworks/Foundation.framework/Foundation --proto '^NSSecureCoding$'
ipsw class-dump "$DSC" /System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore --cat '^UIView.*'
```

| Flag | Effect |
|------|--------|
| `--re -V` | Adds method implementation addresses (`--re` requires `-V`/`--verbose` unless writing `--headers`). Each address is a `// 0x…` line directly above its method: filter with `grep -B1`, and feed the address to `ipsw dyld disass --vaddr` |
| `--refs` | Also dumps ObjC class/selector references |
| `--deps` | Also dumps the private frameworks the dylib imports |
| `--demangle` | Demangles Swift names that appear in ObjC metadata |

## Write header files

```bash
ipsw class-dump "$DSC" /System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices \
  --headers -o ./headers/SpringBoardServices/
```

`--headers` cannot be combined with `--diff`.

## Find which dylib defines a class

```bash
# Every image that defines or extends (category) UIApplication; scans the whole cache (~20s)
ipsw dyld search objc "$DSC" --class '^UIApplication$'

# Selectors, protocols, ivars, and categories work the same way
ipsw dyld search objc "$DSC" --sel '^_setBackgroundStyle:$'
ipsw dyld search swift "$DSC" --protocol 'Widget'
```

For per-image answers use `class-dump` or `dyld search objc --image`; `dyld objc class --image`
does not return reliable per-image results.

## Swift

`swift-dump` is marked 🚧 (work in progress) in `--help`: expect gaps on complex generics.

```bash
ipsw swift-dump "$DSC" /System/Library/Frameworks/WidgetKit.framework/WidgetKit
ipsw swift-dump "$DSC" /System/Library/Frameworks/WidgetKit.framework/WidgetKit --type 'Timeline' --demangle
ipsw swift-dump "$DSC" /System/Library/Frameworks/WidgetKit.framework/WidgetKit --headers -o ./swift-headers/
```

Filters: `--type`, `--proto`, `--ext`, `--ass` (associated types), all regexes. `--extra` dumps the
remaining Swift sections.

## Diff a dylib between releases

The positional DSC is the **new** one and `--diff` takes the **old** one. The output is a
markdown ` ```diff ` block with per-section counts (`+added -removed ~changed`) followed by the
changed members. It runs in about a second per dylib.

```bash
ipsw class-dump "$NEW_DSC" /System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices \
  --diff "$OLD_DSC"
# @@ Classes: +0 added, -0 removed, ~2 changed @@
#  SBSHomeScreenService
# +   -addFileStackWithURL:preferredDisplayName:

ipsw swift-dump "$NEW_DSC" /System/Library/Frameworks/WidgetKit.framework/WidgetKit \
  --diff "$OLD_DSC" > WidgetKit.swift.diff.md
# @@ Types: +88 added, -29 removed, ~23 changed @@
```

Swift diffs of large frameworks run to thousands of lines: redirect to a file and read the
counts line first.

`class-dump --diff` compares methods and `@property` declarations, including their encoded
attributes, so a changed backing ivar shows up:

```text
+   @property -wallpaperDimmed [GisWallpaperDimmed,N,R,TB]
-   @property -configurationType [N,R,Tq]
+   @property -configurationType [N,R,Tq,V_configurationType]
``` To find *which* dylibs changed before diffing them one by one, use
`ipsw diff` or `ipsw dyld info --diff` (see `diffing.md`).

## Standalone Mach-Os

```bash
ipsw class-dump /path/to/binary
ipsw class-dump --arch arm64e /path/to/universal/binary   # fat binaries prompt for an arch without --arch
```

On macOS 11 and later, system frameworks exist only inside the host DSC; dump them from there,
not from `/System/Library/Frameworks/...` on disk.
