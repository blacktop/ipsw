# Sandbox Profile Analysis (`ipsw sb`)

Decode, query, and diff the sandbox profiles compiled into a kernelcache: capability questions
("which profiles can open this IOKit user client?"), attack-surface mapping, and tracking
sandbox changes between releases.

## Contents
- [Commands](#commands)
- [Flag letters](#flag-letters)
- [List and decompile](#list-and-decompile)
- [Capability queries](#capability-queries)
- [Diff between releases](#diff-between-releases)
- [Offline blobs](#offline-blobs)
- [Compile and live checks (macOS)](#compile-and-live-checks-macos)

Examples assume `KC` points at a kernelcache.

## Commands

| Command | Purpose |
|---------|---------|
| `sb list "$KC"` | Profile names (`--type all` also lists protobox and profile collections) |
| `sb opts "$KC"` | Sandbox operation names defined in the kernel |
| `sb opts --diff "$OLD_KC" "$NEW_KC"` | Operations added or removed between two kernels |
| `sb dec "$KC" [PROFILE]` | Decompile to SBPL (default), `--format sbasm`, or `--format json` |
| `sb graph export "$KC" -O graph.json` | Build the cross-profile graph once for fast queries |
| `sb query <kind> <TARGET> --graph graph.json` | Which profiles allow an operation on a target |
| `sb dump "$KC"` | Write raw blobs (`sandbox_collection.bin`, `sandbox_profile.bin`, `sandbox_protobox.bin`) next to the kernelcache |
| `sb cmpl <FILE.sb> -o <DIR>` | Compile SBPL source to `profile.bin` (macOS) |
| `sb check <PID> -o all\|mach\|inspect\|file` | Sandbox state of a running process (macOS) |

## Flag letters

In `sb list`, `dec`, `graph`, and `query`, lowercase `-o` means **operations list file** and
uppercase `-O` means **output** (a path, or for `query` the format `pretty|table|json`). In
`sb cmpl`, `-o` is the output folder, and in `sb check`, `-o` is the check type.

## List and decompile

Use profile names exactly as `sb list` prints them. Many are not bundle-ID style
(`CommCenter`, `accountsd`, `adid`).

```bash
ipsw sb list "$KC"
ipsw sb dec "$KC" com.apple.WebKit.WebContent -O WebContent.sb        # one profile → compileable SBPL
ipsw sb dec "$KC" com.apple.WebKit.WebContent --inline -O WebContent.sb   # fold parent profiles in
ipsw sb dec "$KC" --format json -O all-profiles.json                  # every profile, structured
ipsw sb dec "$KC" CommCenter --full-graph                              # lift the node limit for huge profiles
```

## Capability queries

Export the graph once. On a current iOS kernel this takes about 30 seconds and writes a JSON
file of roughly 500 MB; each later query loads it in about 3 seconds.

```bash
ipsw sb graph export "$KC" -O graph.json

ipsw sb query iokit-open IOSurfaceRootUserClient --graph graph.json
ipsw sb query path-write /private/var/mobile/tmp --graph graph.json
ipsw sb query syscall mmap --graph graph.json            # name or number
ipsw sb query mach-lookup com.apple.mobilegestalt.xpc --graph graph.json
```

| Query kind | Question |
|------------|----------|
| `iokit-open <CLASS>` | Which profiles can open this IOKit user client? |
| `path-read <PATH>` / `path-write <PATH>` | Which profiles can read / write this path? |
| `syscall <NAME\|NUM>` | Which profiles can call this syscall? |
| `sysctl <NAME>` | Which profiles can read or write this sysctl? |
| `mach-lookup <SVC>` / `mach-register <SVC>` | Which profiles can look up / register this Mach service? |
| `preference <DOMAIN>` | Which profiles can read or write this preference domain? |
| `notification <NAME>` | Which profiles can post this notification? |
| `cypher <EXPR>` | Constrained graph query (advanced) |

JSON output for scripting:

```bash
ipsw sb query iokit-open IOSurfaceRootUserClient --graph graph.json -O json \
  | jq -r '.matches[] | select(.decision=="allow") | .profile' | sort -u

ipsw sb query path-write /var/mobile/foo --graph graph.json -O json \
  | jq -r '.matches[] | "\(.profile): \(.guard_string)"'
```

Without `--graph`, a query rebuilds the graph in memory (about 30 seconds per call): fine for a
single lookup, wasteful for more.

## Diff between releases

```bash
ipsw sb opts --diff "$OLD_KC" "$NEW_KC"                   # operation set changes
ipsw sb dec "$OLD_KC" com.apple.WebKit.WebContent -O old.sb
ipsw sb dec "$NEW_KC" com.apple.WebKit.WebContent -O new.sb
diff -u old.sb new.sb                                      # one profile's rule changes
ipsw diff "$OLD_IPSW" "$NEW_IPSW" --sandbox -o ./sbdiff/ --markdown   # every profile, kernelcache-only diff
```

## Offline blobs

`sb dump` output (or any extracted profile blob) can stand in for the kernelcache. Without a
kernelcache the commands need the operations list and the Darwin version:

```bash
ipsw sb opts "$KC" > ops.txt
ipsw kernel version "$KC"                                  # read the Darwin version, e.g. 25.4.0
ipsw sb dec --type profile -i sandbox_profile.bin -o ops.txt --darwin-version 25.4.0
```

`--type` selects `collection` (default), `protobox`, or `profile`.

## Compile and live checks (macOS)

```bash
ipsw sb cmpl my_profile.sb -o ./out/
ipsw sb check 1234 -o all
ipsw sb check 1234 -o file /private/var/tmp/x
```
