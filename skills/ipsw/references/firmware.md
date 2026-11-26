# Firmware Containers and Components

## Contents
- [Inspect an IPSW or OTA](#inspect-an-ipsw-or-ota)
- [Mount a DMG](#mount-a-dmg)
- [DeviceTree](#devicetree)
- [Coprocessor and exclave firmware (`fw`)](#coprocessor-and-exclave-firmware-fw)
- [Trust caches](#trust-caches)
- [IMG4 and IM4P](#img4-and-im4p)
- [AEA-encrypted files](#aea-encrypted-files)
- [OTA internals](#ota-internals)
- [Other formats](#other-formats)

Every `fw` subcommand and `dtree`/`info` accept a local IPSW or, with `--remote`, a URL (see
`download.md` for finding URLs).

## Inspect an IPSW or OTA

```bash
ipsw info "$IPSW"                                  # version, build, devices, kernelcaches, DMGs
ipsw info --json "$IPSW" | jq -c '.devices[] | {product, board, cpu}'
ipsw info --list "$IPSW"                           # every member (also works with --remote URL)
ipsw mdevs "$IPSW"                                 # MobileDevices listed in the filesystem (mounts the DMG)
```

`ota info --json` uses a different schema from `info --json` (see [OTA internals](#ota-internals)).

## Mount a DMG

```bash
ipsw mount fs "$IPSW" --detach        # filesystem; also app, sys, exc (dyld caches), rdisk, rosetta
# …work under the printed mount point…
hdiutil detach '<mount point>'        # the exact command is printed by --detach
```

Without `--detach` the command blocks until Ctrl+C. Mounting extracts the DMG from the IPSW
(and decrypts AEA images) into the current directory first: several GB for a current iOS
filesystem. Universal macOS IPSWs need `--device` for `sys`; encrypted DMGs take `--pem-db`,
or `--key`/`--lookup` for old ones. Scan a mount point as a folder (`ipsw macho search <dir>`,
`ipsw ent --sqlite ent.db --input <dir>`) to avoid repeating the extraction.

## DeviceTree

```bash
ipsw dtree "$IPSW" --summary                        # model, board, product name
ipsw dtree --remote "$URL" --json > dt.json
jq -r '.. | objects | to_entries[]? | select((.value|type)=="object" and (.value|has("compatible")))
       | "\(.key)\t\(.value.compatible|if type=="array" then join(",") else tostring end)"' dt.json
ipsw dtree DeviceTree.v53ap.im4p --summary          # a single extracted IM4P works too
```

On a remote **OTA** URL, `dtree` needs the whole OTA and asks for confirmation (`-y` agrees to a
multi-GB download). Universal macOS images hold several DeviceTrees: select with `--filter`.

## Coprocessor and exclave firmware (`fw`)

| Command | Content |
|---------|---------|
| `fw exclave --remote "$URL" --info` | exclave bundle sections (`ktxt`, `rtxt`, `utxt`, `kdat`, …) and compartments |
| `fw exclave <bundle.im4p> -o ./exc/` | extract compartments (`SYSTEM/kernel`, `APP/roottask`, `APP/sharedcache`, …) as Mach-Os |
| `fw ane --remote "$URL" --info` | Apple Neural Engine firmware Mach-O |
| `fw aop --remote "$URL" --info` | Always-On Processor bundle ranges |
| `fw dcp --remote "$URL" --info` | Display Coprocessor bundle; `-o` extracts a Mach-O |
| `fw gpu --remote "$URL" -o ./gpu/` | AGX GPU firmware split into per-core blobs (no `--info`; always extracts) |
| `fw iboot --remote "$URL" --version` | iBoot version (`--strings` dumps strings; `-o` extracts) |
| `fw ibootim --remote "$URL" --info` | iBoot boot images (recovery screens) |
| `fw c1 "$IPSW" --info` | C1 modem firmware (FTAB entries) |
| `fw ave`, `fw cam` | video encoder / camera firmware |

With `--info`, these commands read firmware into a temporary directory and remove it
afterwards; `fw aop` keeps a cache of IM4Ps under `$TMPDIR`. Remote `--info` still transfers the
component itself (about 50 MB for the exclave bundles). Releases up to 3.1.725 leave the fetched
files under `./<BUILD>__<DEVICE>/`, so run them from a scratch directory there.

The exclave bundle picker appears only when stdin and stdout are both terminals; otherwise the
`.restore.` bundle is skipped automatically. Extracted compartments are ordinary Mach-Os:
`ipsw macho info ./exc/APP/sharedcache`.

To pin down the SPTM/TXM builds, extract and read their version load commands:

```bash
ipsw extract --remote --sptm -o ./fw/ "$URL"
ipsw macho info ./fw/<BUILD>__<DEVICE>/Firmware/sptm.<SOC>.release | grep -E 'LC_UUID|LC_SOURCE_VERSION'
```

## Trust caches

```bash
ipsw fw tc --remote "$URL" --json > tc.json
jq -r 'to_entries[] | "\(.key)\t\(.value.num_entries)"' tc.json                      # entries per DMG
jq -c '[.[] | .entries[] | .constraint_category // 0] | group_by(.) | map({cat: .[0], n: length})' tc.json
jq --arg h "$CDHASH" '.[] | .entries[] | select(.cdhash == $h)' tc.json               # is this cdhash trusted?
```

A binary's CDHash comes from `ipsw dyld image "$DSC" <PATH> --no-color` (same build as the
trust cache) or `ipsw macho info --sig <BIN>`.

## IMG4 and IM4P

```bash
ipsw img4 info file.img4                       # IM4P / IM4M / IM4R summary (--json)
ipsw img4 extract --im4p -o ./out/ file.img4   # payload, decompressed (--raw keeps it compressed)
ipsw img4 im4p info --json payload.im4p        # type, compression, size, encrypted?
ipsw img4 im4p extract payload.im4p -o payload.bin
ipsw img4 im4p extract --kbag payload.im4p     # keybags of an encrypted payload
ipsw img4 im4m info manifest.im4m              # manifest properties
ipsw img4 im4m verify manifest.im4m            # check against a build manifest (see --help)
```

Old encrypted payloads take `--iv/--key` or `--lookup` (theapplewiki keys). `img4 create`,
`im4p create`, and `im4r create` build containers.

## AEA-encrypted files

```bash
ipsw fw aea --info file.aea          # AEA header and auth data
ipsw fw aea --id file.aea            # file ID (offline)
ipsw fw aea --key file.aea           # fetch the decryption key (needs network or --pem/--pem-db)
ipsw fw aea file.aea -o ./out/ --pem-db pem.json      # decrypt
```

Key sources and which command takes which key flag: see `download.md`, "Encrypted (AEA) images".

## OTA internals

ipsw-downloaded AEA OTAs keep their key in the filename (`..._KEY_[<base64>]_<id>.aea`);
every `ota` subcommand picks it up automatically.

```bash
ipsw ota info "$OTA"                                   # version, build, devices, cryptexes
ipsw ota info --json "$OTA" | jq -c '.Plists.system_version'
ipsw ota ls "$OTA"                                     # asset files (kernelcache, firmware, cryptex DMGs)
ipsw ota ls "$OTA" --bom | grep 'LaunchDaemons/'       # every filesystem path in the update (fast)
ipsw ota extract "$OTA" --pattern 'LaunchDaemons/com\.apple\.securityd\.plist$' --confirm -o ./ota/
ipsw ota extract "$OTA" --kernel -o ./ota/
ipsw ota extract "$OTA" --dyld --dyld-arch arm64e -o ./ota/
ipsw ota extract "$OTA" --cryptex system -o ./ota/     # a cryptex as a DMG (full OTAs)
```

- Search the BOM (`ota ls --bom`) before extracting: it lists every path in seconds.
- `ota extract --pattern` on payloadv2 content needs `--confirm` when there is no terminal
  (without it the command stops with an error; 3.1.725 skipped the search silently).
  `--range '<regex>'` limits which payload chunks are searched.
- `ota ls --payload --json` prints one JSON array per matching payload chunk (a stream, so
  `jq -s 'add'` merges them); no match prints nothing.
- `ota payload <OTA> <payload>` lists a raw, PBZX, or PBZM payloadv2 file; PBZM needs Apple's
  `aa` tool with PBZM support.
- `ota patch rsr` applies Rapid Security Response patches; `ota patch bxdiff` handles BXDIFF50
  updates.

## Other formats

| Command | Does |
|---------|------|
| `ipsw plist <file>` | any plist (binary or XML) as JSON: pipe to `jq` |
| `ipsw pbzx <file>` | decompress a pbzx stream |
| `ipsw lsbom <file>` | list a BOM |
| `ipsw car Assets.car --metadata-only --json` | inventory an asset catalog; `-o <dir>` exports renditions (`--dry-run` previews) |
| `ipsw comp <file>` / `ipsw decomp <file>` | libcompression compress / decompress |
| `ipsw img3 info <file>` | legacy Img3 containers |
