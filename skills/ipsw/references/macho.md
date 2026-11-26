# Mach-O Binary Analysis

## Contents
- [Universal (fat) binaries first](#universal-fat-binaries-first)
- [Inspect](#inspect)
- [Entitlements and code signature](#entitlements-and-code-signature)
- [Disassemble](#disassemble)
- [Addresses](#addresses)
- [Search many binaries at once](#search-many-binaries-at-once)
- [Fileset Mach-Os (kernelcaches)](#fileset-mach-os-kernelcaches)
- [Modify: lipo, sign, patch](#modify-lipo-sign-patch)

For dylibs inside a dyld_shared_cache, use `ipsw dyld macho` / `ipsw dyld ...` instead (see
`dyld.md`); for kernelcaches see `kernel.md`.

## Universal (fat) binaries first

On a fat binary, every `ipsw macho` command without `--arch` opens an interactive
architecture picker, which fails without a terminal. Most macOS binaries are fat
(`/bin/ls` holds x86_64, arm64e, and arm64e.x1 slices). List slices with the system tools,
then pass one:

```bash
lipo -archs /bin/ls            # or: file /bin/ls
ipsw macho info --arch arm64e --header /bin/ls
```

Binaries pulled from iOS firmware are usually thin and need no `--arch`.

## Inspect

```bash
ipsw macho info "$BIN"                 # header, load commands, and summary
ipsw macho info --json "$BIN" | jq .   # everything, machine-readable
```

| Flag | Prints |
|------|--------|
| `--header` / `--loads` | mach header / load commands |
| `--symbols` (`--demangle`) | symbol table |
| `--starts` | function starts |
| `--strings` | C strings |
| `--fixups` | chained fixups |
| `--objc` / `--objc-refs` | ObjC metadata / references |
| `--swift` / `--swift-all` | Swift metadata |
| `--split-seg` | split-seg info |

## Entitlements and code signature

```bash
ipsw macho info --ent "$BIN"        # entitlements plist
ipsw macho info --ent-der "$BIN"    # DER-encoded entitlements
ipsw macho info --sig "$BIN"        # code directory, requirements, CMS
ipsw macho info --dump-cert "$BIN"  # signing certificate chain
```

To search entitlements across a whole firmware image, use `ipsw ent` (see `entitlements.md`).

## Disassemble

```bash
ipsw macho disass "$BIN" --symbol _main --count 60
ipsw macho disass "$BIN" --vaddr 0x100003f10
ipsw macho disass "$BIN" --entry            # entry point
ipsw macho disass "$BIN" --section __TEXT.__text
ipsw macho disass "$BIN" --symbol _main --json
```

`--dec --dec-llm <provider>` decompiles via an LLM provider (needs that provider's API key).

## Addresses

```bash
ipsw macho a2s "$BIN" 0x100003f10          # address → symbol
ipsw macho a2o "$BIN" 0x100003f10          # address → file offset
ipsw macho o2a "$BIN" 0x3f10               # file offset → address
ipsw macho dump "$BIN" 0x100003f10 --size 64
```

## Search many binaries at once

`macho search` scans every Mach-O in a folder or inside an IPSW's filesystem (no manual
extraction). All criteria are regular expressions.

```bash
ipsw macho search "$IPSW" --sym '_SecTaskCopyValueForEntitlement'
ipsw macho search "$IPSW" --import 'libMobileGestalt'
ipsw macho search ./extracted/ --sel 'shouldAcceptNewConnection'
ipsw macho search "$IPSW" --launch-const 'is-sip-protected'
ipsw macho search "$IPSW" --section '__TEXT.__swift5_types'
```

Other criteria: `--protocol`, `--category`, `--ivar`, `--load-command`, `--uuid`, `--mte`. The
ObjC criteria (`--class`, `--sel`, `--protocol`, `--category`, `--ivar`) are mutually exclusive:
one per run.
Encrypted (AEA) macOS images need `--pem-db`.

## Fileset Mach-Os (kernelcaches)

```bash
ipsw macho info --all-fileset-entries "$KC" | head
ipsw macho info --fileset-entry com.apple.kernel --header "$KC"
ipsw macho info --fileset-entry com.apple.security.sandbox --extract-fileset-entry --output ./entries/ "$KC"
```

## Modify: lipo, sign, patch

```bash
# Thin a fat binary; --output is a directory, the file lands at ./out/<name>.<arch>
ipsw macho lipo --arch arm64e --output ./out/ /path/to/fat

# Merge thin binaries into a universal one
ipsw macho bbl arm64_binary arm64e_binary --output universal_binary

# Ad-hoc sign (non-ad-hoc needs --cert <p12> --pw <password>); write to a new file with -o or in place with -f
ipsw macho sign --ad-hoc --ent entitlements.plist -o signed_binary "$BIN"

# Load commands: add / mod / rm
ipsw macho patch add "$BIN" LC_RPATH @executable_path/../Frameworks -o patched_binary
ipsw macho patch mod "$BIN" LC_BUILD_VERSION iOS 16.3 16.3 ld 820.1 -o patched_binary
ipsw macho patch rm "$BIN" LC_RPATH @executable_path/Frameworks -o patched_binary
```

Patching invalidates the code signature; add `--re-sign` to ad-hoc sign the result.
`macho sign --id` sets the code-signing identifier (for example `com.example.tool`), not a
keychain identity.
