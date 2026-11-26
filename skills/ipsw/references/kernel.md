# Kernelcache and KEXT Analysis

## Contents
- [Get a kernelcache](#get-a-kernelcache)
- [Identify and list](#identify-and-list)
- [Name symbols in a stripped kernel](#name-symbols-in-a-stripped-kernel)
- [Disassemble](#disassemble)
- [C++ classes and IOKit](#c-classes-and-iokit)
- [Syscalls, Mach traps, MIG](#syscalls-mach-traps-mig)
- [Extract KEXTs](#extract-kexts)
- [Compare two kernels](#compare-two-kernels)
- [Types from a KDK](#types-from-a-kdk)

Examples assume `KC` points at a kernelcache such as `kernelcache.release.iPhone18,1`.

## Get a kernelcache

```bash
ipsw extract --kernel -o ./extracted/ "$IPSW"            # local IPSW
ipsw extract --kernel --remote -o ./extracted/ "$URL"    # remote IPSW, downloads only the kernel (~75 MB)
ipsw kernel dec kernelcache.im4p --output kernelcache.decompressed   # only for a raw compressed IM4P
```

`extract --kernel` writes an already-decompressed Mach-O. Modern kernelcaches are `MH_FILESET`
Mach-Os: `com.apple.kernel` plus one fileset entry per KEXT.

## Identify and list

```bash
ipsw kernel version "$KC"          # Darwin version and xnu build (--json: darwin, xnu, type, cpu)
ipsw kernel kexts "$KC"            # every KEXT with its version (--json for scripting)
ipsw kernel symbolsets "$KC"       # KPI symbol sets
```

## Name symbols in a stripped kernel

Release kernelcaches are stripped: `--symbol` lookups fail and functions print as `sub_<addr>`.
`kernel symbolicate` recovers names. On its own it names syscalls, Mach traps, MIG routines, and
C++ methods (~12,800 symbols on iOS 26, about 4 seconds); signatures from
[blacktop/symbolicator](https://github.com/blacktop/symbolicator) add most other functions:

```bash
mkdir -p ./syms && ipsw kernel symbolicate --json -o ./syms/ "$KC"                   # no signatures

git clone https://github.com/blacktop/symbolicator
mkdir -p ./syms && ipsw kernel symbolicate --signatures symbolicator/kernel --json -o ./syms/ "$KC"
#   Symbolication STATS  matched=4962 missed=1367 percent=78.4%   (about 10s)

# Nearest symbol for an address, from the saved map (instant)
ipsw kernel symbolicate --lookup 0xfffffe000ab90040 ./syms/kernelcache.release.iPhone18,1.symbols.json
```

The `.symbols.json` map's keys are decimal addresses. For development kernels with full
symbols, download the matching KDK (`ipsw download kdk`, see `download.md`).

## Disassemble

```bash
ipsw macho disass "$KC" --fileset-entry com.apple.kernel --vaddr 0xfffffe000ab90040 --count 40
ipsw macho disass "$KC" --fileset-entry com.apple.security.sandbox --vaddr <ADDR>
```

A fileset kernelcache needs `--fileset-entry` (or `--all-fileset-entries`). IOKit's core code
is part of `com.apple.kernel`; `com.apple.iokit.IOKit` in `kernel kexts` is a codeless
pseudo-KEXT, not a fileset entry. `--symbol` works only on a symbolized kernel (a KDK
development kernel), so on release kernels resolve names with `kernel symbolicate` and
disassemble by `--vaddr`. The first disassembly writes a `<KC>.a2s` cache beside the file.

## C++ classes and IOKit

Kernelcaches contain no ObjC; use `kernel cpp` to recover C++ classes (fast, a few seconds).

```bash
ipsw kernel cpp "$KC" | grep -i UserClient                # class names, sizes, bundles
ipsw kernel cpp "$KC" --class IOSurfaceRootUserClient --inheritance
ipsw kernel cpp "$KC" --class IOSurfaceRootUserClient --methods   # vtable slots with target addresses
ipsw kernel cpp "$KC" --entry com.apple.iokit.IOSurface --json > iosurface-classes.json
```

Every IOUserClient subclass (following parents transitively), and which appeared or vanished
between two builds. In `--json`, `SuperIndex` indexes the parent in the same array:

```bash
Q='. as $a | def up($i): if $i==null or $i<0 then empty else $a[$i].Name, up($a[$i].SuperIndex) end;
   .[] | select([up(.SuperIndex)] | index("IOUserClient")) | "\(.Bundle)\t\(.Name)"'
ipsw kernel cpp --json "$OLD_KC" | jq -r "$Q" | sort > old.tsv
ipsw kernel cpp --json "$NEW_KC" | jq -r "$Q" | sort > new.tsv
diff old.tsv new.tsv
```

Each KEXT's Info.plist, including IOKit personalities, is in `kernel kexts --json`:

```bash
ipsw kernel kexts --json "$KC" | jq -r '.[] | .id as $k | (.io_kit_personalities // {}) | to_entries[]
  | select(.value.IOUserClientClass) | "\($k)\t\(.value.IOClass)\t\(.value.IOUserClientClass)"' | sort -u
```

Feed class names to `ipsw sb query iokit-open <CLASS>` (see `sandbox.md`) to see which sandbox
profiles may open them.

## Syscalls, Mach traps, MIG

```bash
ipsw kernel syscall "$KC"      # BSD syscall table: number, handler address, prototype
ipsw kernel mach "$KC"         # mach_trap_table
ipsw kernel mig "$KC"          # MIG subsystems and their routines (_Xmach_vm_allocate_external, …)
```

## Extract KEXTs

```bash
ipsw kernel extract "$KC" com.apple.security.sandbox -o ./kexts/
ipsw kernel extract "$KC" --all -o ./kexts/
ipsw kernel extract "$KC" com.apple.driver.AppleMobileFileIntegrity -o ./kexts/ --imports   # resolve imported symbol names
```

Name KEXTs by full bundle ID. A short name matches by case-insensitive suffix and the first hit
wins: `IOKit` silently extracts `com.apple.driver.ASIOKit`. The output file is named exactly as
you typed the argument, with no `.kext` suffix, and it is stripped like the kernel.

## Compare two kernels

```bash
# Changed KEXT versions (color table in a terminal; plain word diff when piped or --no-color)
ipsw kernel kexts --diff "$OLD_KC" "$NEW_KC"
#   com.apple.AGXG18P (3[-41.11-]{+50.37+})

# One "id version" line per KEXT, for scripting
ipsw kernel kexts --json "$OLD_KC" | jq -r '.[] | "\(.id) \(.version)"' | sort > kexts.old.txt
ipsw kernel kexts --json "$NEW_KC" | jq -r '.[] | "\(.id) \(.version)"' | sort > kexts.new.txt
diff kexts.old.txt kexts.new.txt

# Sandbox operation changes between the two kernels
ipsw sb opts --diff "$OLD_KC" "$NEW_KC"
```

For function-level changes across a whole release, `ipsw diff` on the two IPSWs (see
`diffing.md`) covers KEXTs, DSC dylibs, and filesystem binaries in one report.

## Types from a KDK

Kernel Development Kits ship symbolized kernels with CTF type data (`ipsw download kdk`).

```bash
K=/Library/Developer/KDKs/<KDK>.kdk/System/Library/Kernels/kernel.development.t6020
ipsw kernel ctfdump "$K" task            # one type as a C definition
ipsw kernel ctfdump "$K" > kernel-types.h    # every type (no type argument)
```

`ipsw kernel dwarf` (marked 🚧 WIP) reads DWARF from the KDK's `*.dSYM` bundles, not from the
stripped `kernel.*` binaries; `--diff -t <TYPE> <OLD.dSYM> <NEW.dSYM>` compares a struct across
two KDKs.
