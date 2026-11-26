# Diffing Releases

What changed between two builds: which binaries, functions, APIs, entitlements, sandbox rules,
and firmware. Start broad with `ipsw diff`, then drill into one component with the targeted
commands.

## Contents
- [Full release diff](#full-release-diff)
- [Targeted diffs](#targeted-diffs)
- [Patch-hunting workflow](#patch-hunting-workflow)

## Full release diff

```bash
ipsw diff "$OLD_IPSW" "$NEW_IPSW" -o ./diff/ --markdown
ipsw diff "$OLD_IPSW" "$NEW_IPSW" -o ./diff/ --markdown --fw --launchd --ent --feat
```

By default it compares KEXTs, dyld_shared_cache dylibs, and filesystem Mach-Os (added and
removed binaries, and per-binary changes). Opt-in sections:

| Flag | Adds |
|------|------|
| `--ent` | per-binary entitlement changes |
| `--starts` | function-starts deltas (new or removed functions) |
| `--strs` | C-string changes |
| `--fw` | other firmware (iBoot, SEP, coprocessors) |
| `--launchd` | launchd configuration |
| `--feat` | feature flags |
| `--sandbox` | compiled sandbox profiles (on its own, runs a kernelcache-only diff) |
| `--loc` | localized string resources |
| `--files` | file lists |
| `--kdk OLD --kdk NEW` | symbolized kernel diff from two KDK kernels |
| `-s <symbolicator>/kernel` | symbolicator signatures for kernel function names |

Output: `--markdown`, `--html`, or `--json` into `-o <folder>`. Results are cached per IPSW
pair (`--clean` rebuilds, `--no-cache` skips the cache). A full diff reads both filesystem
images, so it needs both IPSWs locally, takes a long time, and uses a lot of temporary disk.
OTA-to-OTA diffs need full OTAs, run on macOS only, and take `--key-db`/`--key-val` for AEA
keys. Universal macOS IPSWs take `--device` to pick the hardware variant.

## Targeted diffs

Each of these runs in seconds on local artifacts.

| Question | Command | Reference |
|----------|---------|-----------|
| Which dylibs were added, removed, or re-versioned? | `ipsw dyld info --dylibs --delta "$OLD_DSC" "$NEW_DSC"` | `dyld.md` |
| How did one dylib's ObjC API change? | `ipsw class-dump "$NEW_DSC" <DYLIB> --diff "$OLD_DSC"` | `class-dump.md` |
| How did one dylib's Swift API change? | `ipsw swift-dump "$NEW_DSC" <DYLIB> --diff "$OLD_DSC"` | `class-dump.md` |
| Which KEXTs changed version? | `ipsw kernel kexts --diff "$OLD_KC" "$NEW_KC"` (or the `--json` recipe) | `kernel.md` |
| Which sandbox operations appeared or vanished? | `ipsw sb opts --diff "$OLD_KC" "$NEW_KC"` | `sandbox.md` |
| How did one sandbox profile change? | `sb dec` each kernel, then `diff -u` | `sandbox.md` |
| Which entitlements changed? | `ipsw diff ... --ent`, or query an `ent` database per version | `entitlements.md` |

`class-dump --diff`, `swift-dump --diff`, and the `--diff` of `dyld info`/`kernel kexts` all take
the old and new artifacts in different positions: check the table above rather than assuming
`OLD NEW` order.

## Patch-hunting workflow

Copy this checklist and work through it:

```
- [ ] 1. Pin both builds: `ipsw info --remote "$URL"` (or local) for version/build/device
- [ ] 2. Broad diff: `ipsw diff OLD NEW -o ./diff/ --markdown --starts --ent`
- [ ] 3. Pick candidates: binaries/KEXTs whose function starts or strings changed
- [ ] 4. API view: `class-dump --diff` / `swift-dump --diff` on candidate dylibs
- [ ] 5. Code view: disassemble the changed functions in both builds (`dyld disass`, `macho disass`)
- [ ] 6. Confirm: the same address range differs in both disassemblies, not just relocations
```

For kernel candidates, symbolicate both kernels first (`kernel.md`) so the diff and disassembly
show names instead of `sub_<addr>`.
