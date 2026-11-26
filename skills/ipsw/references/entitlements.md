# Entitlements Research

## Contents
- [One binary](#one-binary)
- [Search a firmware image without a database](#search-a-firmware-image-without-a-database)
- [Build a database](#build-a-database)
- [Query the database](#query-the-database)
- [Track changes between releases](#track-changes-between-releases)

## One binary

```bash
ipsw macho info --ent "$BIN"          # plist
ipsw macho info --ent-der "$BIN"      # DER
```

For a binary inside a DSC, extract it first (`ipsw dyld extract`) or use the database below.
Fat macOS binaries need `--arch` (see `macho.md`).

## Search a firmware image without a database

`--fs` scans the Mach-Os in an IPSW's filesystem directly: good for one-off questions.

```bash
# Binaries that have both entitlements
ipsw ent --fs --has com.apple.private.security.no-sandbox,platform-application --file-only "$IPSW"

# Binaries with one entitlement but not another
ipsw ent --fs --has com.apple.private.tcc.allow --without com.apple.private.tcc.manager "$IPSW"

# Machine-readable
ipsw ent --fs --has com.apple.private.security.no-sandbox --format jsonl "$IPSW"
```

Scanning the filesystem unpacks (and, for AEA images, decrypts) the filesystem DMG into the
current directory and mounts it under `/tmp` on macOS: expect several GB of temporary disk
use per run. Run it from a directory with space. For repeated questions, build a database once.

## Build a database

```bash
ipsw ent --sqlite ent.db --ipsw "$IPSW"
ipsw ent --sqlite ent.db --ipsw a.ipsw --ipsw b.ipsw        # one --ipsw per file
ipsw ent --sqlite ent.db --input ./extracted_binaries/      # a folder of Mach-Os
ipsw ent --sqlite ent.db --ipsw new.ipsw --replace --dry-run   # preview replacing an older build of the same version
```

`--ipsw` takes one file per flag: a shell glob such as `--ipsw *.ipsw` breaks as soon as it
matches two files. Generate the flags instead:

```bash
set --; for f in ./*.ipsw; do set -- "$@" --ipsw "$f"; done
ipsw ent --sqlite ent.db "$@"
```

PostgreSQL works the same way with `--pg-host`, `--pg-user`, `--pg-database` (and
`--pg-password`, `--pg-sslmode`).

## Query the database

Key, value, and file arguments are patterns.

```bash
ipsw ent --sqlite ent.db --key com.apple.private.security.no-sandbox
ipsw ent --sqlite ent.db --key 'com.apple.private.tcc' --version 27.0
ipsw ent --sqlite ent.db --value LockdownMode
ipsw ent --sqlite ent.db --file WebContent            # every entitlement of matching files
ipsw ent --sqlite ent.db --key 'com.apple.private' --file-only --limit 500
ipsw ent --sqlite ent.db --stats
```

`--limit` defaults to 100 results; raise it for broad keys.

## Track changes between releases

```bash
ipsw ent --sqlite ent.db --ipsw old.ipsw --ipsw new.ipsw
ipsw ent --sqlite ent.db --key 'com.apple.private' --version <OLD_VERSION> --limit 100000 > old.txt
ipsw ent --sqlite ent.db --key 'com.apple.private' --version <NEW_VERSION> --limit 100000 > new.txt
diff old.txt new.txt
```

`ipsw diff old.ipsw new.ipsw --ent` adds per-binary entitlement changes to a full release
diff (see `diffing.md`).

Pair entitlement findings with sandbox queries (`sandbox.md`): an entitlement often only
matters when the process's sandbox profile also permits the operation.
