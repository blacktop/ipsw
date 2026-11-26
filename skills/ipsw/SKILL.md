---
name: ipsw
description: Reverse-engineers Apple firmware and binaries with the ipsw CLI. Inspects IPSWs and OTAs remotely or locally; extracts kernelcaches, dyld_shared_cache, exclave, SEP, and coprocessor firmware; disassembles and cross-references DSC dylibs, KEXTs, and Mach-Os; dumps and diffs ObjC/Swift headers; decompiles and queries sandbox profiles; searches entitlements; symbolicates crashes and panics; and diffs releases. Use for iOS/macOS internals, private frameworks, kernel or firmware research, and Apple security research, even when ipsw is not named.
license: MIT
metadata:
  version: "2.1.0"
  ipsw-version: "3.1.752-10-g30a209c6d"
---

# ipsw

`ipsw` is one CLI for Apple firmware work, organized into command groups (`download`,
`extract`, `dyld`, `kernel`, `macho`, `fw`, `sb`, `ent`, `diff`, `symbolicate`, `idev`, ...).
Install it with `brew install blacktop/tap/ipsw` (other platforms: github.com/blacktop/ipsw
releases). Remote and download commands need network access; `idev` needs a USB-connected
device. The commands and flags in this skill match ipsw 3.1.752 (commit 30a209c6d); on 3.1.725
and earlier, apply the "Older releases" table below. Flags change between releases:
`ipsw version` shows the installed build, and `ipsw <group> <command> --help` is the source of
truth. Commands marked 🚧 in `--help` are works in progress.

Examples use these shell variables (POSIX sh/bash/zsh syntax):

```bash
IPSW=./iPhone18,1_26.4_23E246_Restore.ipsw   # local IPSW or OTA
URL=https://updates.cdn-apple.com/...          # remote IPSW or OTA (see "Triage a release")
DSC=./dyld_shared_cache_arm64e                 # main file of an extracted cache; subcaches beside it
KC=./kernelcache.release.iPhone18,1            # extracted kernelcache
DEVICE=iPhone18,1                              # any product type from `ipsw device-list`
```

## Working rules

These are where agents most often go wrong with ipsw.

1. **Make every choice explicit on the command line.** Without a terminal, ipsw cannot prompt:
   the command stops with an error such as "use --confirm to proceed unattended" (older
   releases skip the step silently; see "Older releases" below). Pass the selection instead:
   - A short dylib name that matches several images (`UIKit`, `SwiftUI`, `SpringBoard`) fails.
     Pass the full install path, found with
     `ipsw dyld info --dylibs --json "$DSC" | jq -r '.dylibs[].name' | grep -i <name>`.
   - Fat Mach-Os need `--arch arm64e`; multi-device IPSWs need `--device <product-type>`.
   - Downloads and payload searches need `-y`/`--confirm` (`download`, `ota extract --pattern`).
   - `ipsw mount` blocks until Ctrl+C: pass `--detach`, then run the `hdiutil detach …`
     command it prints.
   - `idev crash pull` needs a path or `--all`; `idev syslog` streams forever unless given
     `-t <seconds>`.
2. **Read remotely before downloading.** A current IPSW is 10–15 GB, but `--remote` commands
   fetch only what they need: `info --remote` (KB), `extract --kernel --remote` (~75 MB),
   `fw <component> --remote` (MBs to tens of MB), and on ipsw 3.1.750 and later
   `extract --remote --files --ranged` reads single filesystem files without fetching the DMG.
   A remote `extract --dyld` is several GB. Download whole images only for filesystem-wide work.
3. **Keep large output out of the conversation.** Prefer `--json | jq`, write to files with
   `-o`/`--output`, and read the head or counts first. Dumps of a whole DSC or kernel run to
   millions of lines.
4. **Expect one-time costs and plan for them:**
   - First `dyld disass`/`xref` on a cache builds `<DSC>.a2s` (minutes, ~1.5 GB).
   - `sb graph export` takes ~30 s and writes ~500 MB, then makes queries take ~3 s.
   - Filesystem scans (`ent --fs`, `macho search <IPSW>`, `diff`) unpack and decrypt a
     multi-GB DMG into the current directory.
   - The first `download appledb` clones ~600 MB into `~/.config/ipsw/appledb`; `--no-update`
     (also on `download tss`) reuses the existing checkout.
5. **Verify before reporting.** Cross-check an address↔symbol result with the opposite
   command (`a2s` vs `symaddr`), confirm a crash log's build matches the firmware before
   trusting symbolication, and list extraction output (or use `extract --json`) rather than
   assuming file names.

## Choose a workflow

| Task | Start with | Details |
|------|-----------|---------|
| Find, read remotely, download, or extract firmware | `ipsw download appledb ... --urls`, `ipsw extract` | `references/download.md` |
| Coprocessor, exclave, iBoot, SEP, IMG4, AEA, OTA internals | `ipsw fw <component>`, `ipsw img4`, `ipsw ota` | `references/firmware.md` |
| Userspace code in the dyld_shared_cache | `ipsw dyld a2s / disass / xref` | `references/dyld.md` |
| ObjC/Swift interfaces of private frameworks | `ipsw class-dump`, `ipsw swift-dump` | `references/class-dump.md` |
| Standalone binaries: info, entitlements, signing | `ipsw macho info / disass / search` | `references/macho.md` |
| Kernelcache: KEXTs, symbols, C++ classes, syscalls | `ipsw kernel ...` | `references/kernel.md` |
| Sandbox profiles and capability questions | `ipsw sb ...` | `references/sandbox.md` |
| Entitlement search across a firmware image | `ipsw ent ...` | `references/entitlements.md` |
| What changed between two builds | `ipsw diff`, `--diff`/`--delta` variants | `references/diffing.md` |
| Crash logs and panics | `ipsw symbolicate` | `references/symbolication.md` |
| A USB-connected iPhone/iPad | `ipsw idev ...` | `references/device.md` |

## Triage a release without downloading it

```bash
URL="$(ipsw download appledb --os iOS --device "$DEVICE" --latest --release --urls | head -1)"
ipsw info --remote "$URL"                          # version, build, devices, CPU
ipsw info --remote --list "$URL"                   # every file in the IPSW, with sizes
ipsw fw exclave --remote "$URL" --info             # exclave bundle sections (~50 MB fetched)
KC="$(ipsw extract --kernel --remote --json -o ./fw/ "$URL" | jq -r 'keys[0]')"   # just the kernelcache
ipsw dtree --remote "$URL" --summary               # DeviceTree identity
```

`dl` and `db` are aliases for `download` and `appledb`. `--latest` alone means the newest build
on *any* channel (often a beta): add `--release`, `--beta`, or `--rc`, or pin `--build <BUILD>`
/ `--version <X.Y>`; `--type ota` returns OTA URLs. `ipsw download ipsw --device "$DEVICE"
--latest --urls` gives the newest signed public IPSW without touching AppleDB.

## Userspace: from an address to an explanation

```bash
ipsw dyld a2s "$DSC" 0x18ebfa9c8                                      # symbol + offset
ipsw dyld disass "$DSC" --vaddr 0x18ebfa9a8 --count 60                 # first run builds the .a2s cache
ipsw dyld xref "$DSC" 0x18ebfa9a8 --imports                            # callers in this and dependent dylibs
ipsw dyld imports "$DSC" /System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices
ipsw class-dump "$DSC" /System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore \
  --class '^UIApplication$' --re -V | grep -B1 'BackgroundTask'
```

`--re` (which requires `-V`/`--verbose`) prints each method's implementation address as a
`// 0x…` comment on the line above the method, so keep one line of leading context when
filtering. The addresses feed back into `dyld disass --vaddr`. UIKit's classes live in
`UIKitCore`; `UIKit.framework/UIKit` is a shim with no ObjC.

## Kernel: name, find, disassemble

```bash
ipsw kernel version "$KC"
mkdir -p ./syms && ipsw kernel symbolicate --signatures symbolicator/kernel --json -o ./syms/ "$KC"   # names for a stripped kernel
ipsw kernel cpp "$KC" --class IOSurfaceRootUserClient --inheritance                 # C++ classes (no ObjC in kernels)
ipsw kernel syscall "$KC"                                                           # also: mach, mig, kexts
ipsw macho disass "$KC" --fileset-entry com.apple.kernel --vaddr 0xfffffe000ab90040 --count 40
```

Signatures come from `git clone https://github.com/blacktop/symbolicator`; without
`--signatures`, symbolicate still names syscalls, Mach traps, MIG routines, and C++ methods.
Release kernels are stripped, so disassemble by `--vaddr`. Name KEXTs by full bundle ID: short names match by suffix
(`IOKit` resolves to `com.apple.driver.ASIOKit`).

## What changed between two builds

```bash
ipsw dyld info --dylibs --delta "$OLD_DSC" "$NEW_DSC"          # added/removed/re-versioned dylibs
ipsw class-dump "$NEW_DSC" <DYLIB_PATH> --diff "$OLD_DSC"       # ObjC API diff (new first, --diff old)
ipsw swift-dump "$NEW_DSC" <DYLIB_PATH> --diff "$OLD_DSC" > api.diff.md   # Swift API diff (long)
ipsw kernel kexts --diff "$OLD_KC" "$NEW_KC"
ipsw sb opts --diff "$OLD_KC" "$NEW_KC"
ipsw diff "$OLD_IPSW" "$NEW_IPSW" -o ./diff/ --markdown --starts --ent   # full report (slow, local IPSWs)
```

See `references/diffing.md` for the patch-hunting checklist.

## Capabilities: entitlements and sandbox

```bash
ipsw ent --fs --has com.apple.private.security.no-sandbox --file-only "$IPSW"   # no database needed
ipsw sb graph export "$KC" -O graph.json
ipsw sb query iokit-open IOSurfaceRootUserClient --graph graph.json -O json \
  | jq -r '.matches[] | select(.decision=="allow") | .profile' | sort -u
```

## Crashes and panics

```bash
ipsw symbolicate panic-full-<date>.ips "$IPSW" --peek       # kernel + userspace frames, with disassembly
ipsw symbolicate crash.ips "$DSC" --unslide                  # userspace, addresses usable in static tools
```

The firmware must be the exact build in the log's header (`head -1 <log>.ips | jq -r .os_version`).
Without local firmware, `--server <URL>` queries an `ipswd` symbol server; pass its bearer token
through `IPSW_SYMBOLICATE_API_TOKEN` (see `references/symbolication.md`).

## Pitfalls

- `dyld symaddr` and `dyld disass --symbol` match exact names, not regexes; use
  `symaddr --in <json>` for patterns. The symbol-lookup hint for `disass` is `--symbol-image`
  (`--image` selects whole dylibs to disassemble).
- ObjC instance-method names start with `-` and parse as flags: put them after `--`
  (`ipsw dyld symaddr "$DSC" --image <DYLIB> -- '-[UIApplication endBackgroundTask:]'`).
- `dyld str` searches the whole cache and has no per-image filter.
- `dyld xref --all` disassembles every image (very slow); start without it.
- `extract --dyld` without `--dyld-arch` extracts every architecture in the image.
- `class-dump --re` requires `-V`; the addresses print as `// 0x…` lines above each method.
- In `sb` commands, `-o` is the operations list and `-O` is output.
- `download git` and `device-info` take `--product` / `--prod`, not a positional argument.

## Older releases (ipsw 3.1.725 and earlier)

Check `ipsw version`. These releases behave differently; use the workaround on the right:

| Behavior in 3.1.725 and earlier | Workaround |
|---|---|
| Prompts without a terminal skip the step and exit 0 (`download appledb/ota` "Continue?", `ota extract` payload search) | Always pass `--confirm`/`-y`; check the output rather than the exit status |
| `download tss --signed` exits 0 when unsigned; no `--no-update` | Match `Is still being signed` / `No longer being signed` in the output |
| `download kdk` with no selector exits 0 doing nothing | Pass `--host`, `--build`, `--latest`, or `--all` |
| `dyld a2f <DSC> <ADDR>` fails with `failed to find image containing stub target` | `echo <ADDR> \| ipsw dyld a2f "$DSC" --in /dev/stdin` |
| `dyld webkit --diff` rejects its second argument | `ipsw dyld webkit --json "$DSC" \| jq -r .version` for each cache |
| `dyld info --dylibs --diff/--delta` has no `--json`; `--diff` and `kernel kexts --diff` print ANSI even with `--no-color` | Use `--delta` (markdown) and the `kexts --json` recipe in `references/kernel.md` |
| `class-dump --diff` ignores `@property` changes | Dump the class from both caches and `diff -u` |
| `kernel symbolicate -o <dir>` fails if `<dir>` does not exist | `mkdir -p <dir>` first |
| `fw exclave/dcp/c1 --info` leave fetched firmware under `./<BUILD>__<DEVICE>/` | Run from a scratch directory |
| `extract --remote --kbag` downloads every IM4P whole (~150 MB) | Budget for it, or extract only the IM4Ps you need |
| `extract` has no `--json-format artifacts` | Use plain `--json`: `jq -r 'keys[0]'` after `--kernel`, `.[]` after `--sptm`/`--pattern` |
| `ota ls --payload --json` prints a banner before the JSON | `sed -n '/^\[/,$p'` before `jq` |
| `dyld search objc` prints a `relative method selectors` error for one image | Ignore it; the other results are valid |
| `device-info` and `download git` silently ignore positional arguments | Use `--prod` / `--product` |

## Reference files

Read the one that matches the task; each starts with a table of contents.

- `references/download.md`: finding URLs, remote reads, downloads, extraction, AEA keys, config
- `references/firmware.md`: `info`, `mount`, `dtree`, `fw` components, IMG4, AEA, OTA payloads
- `references/dyld.md`: DSC addresses, disassembly, xrefs, imports, soft links, extraction
- `references/class-dump.md`: ObjC/Swift dumping, header generation, API diffs
- `references/macho.md`: Mach-O info, entitlements, signatures, search, lipo/sign/patch
- `references/kernel.md`: kernel symbols, C++ classes, syscalls/MIG, KEXT extraction, KDK types
- `references/sandbox.md`: profile decompilation, capability queries, sandbox diffs
- `references/entitlements.md`: entitlement search and databases
- `references/diffing.md`: release diffs and the patch-hunting checklist
- `references/symbolication.md`: crash and panic symbolication
- `references/device.md`: `idev` commands for USB-connected devices
