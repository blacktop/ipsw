# Getting Firmware: Find, Read Remotely, Download, Extract

## Contents
- [Decide before downloading](#decide-before-downloading)
- [Find a firmware URL](#find-a-firmware-url)
- [Read a remote IPSW or OTA without downloading it](#read-a-remote-ipsw-or-ota-without-downloading-it)
- [Download](#download)
- [Extract from a local IPSW or OTA](#extract-from-a-local-ipsw-or-ota)
- [Encrypted (AEA) images](#encrypted-aea-images)
- [Other sources](#other-sources)
- [Device identifiers](#device-identifiers)
- [Configuration](#configuration)

## Decide before downloading

A current iOS IPSW is 10–15 GB. Most questions need one component, and `ipsw` reads remote
IPSW/OTA zips with HTTP range requests, fetching only the bytes it needs.

| Need | Command | Transfers |
|------|---------|-----------|
| Version, build, devices, CPU | `ipsw info --remote "$URL"` | a few KB |
| File list | `ipsw info --remote --list "$URL"` | a few KB |
| Kernelcache | `ipsw extract --kernel --remote "$URL"` | ~75 MB |
| Exclave, SEP, SPTM/TXM, iBoot, DeviceTree | `ipsw extract --remote --exclave\|--sep\|--sptm\|--iboot\|--dtree "$URL"` | MBs to tens of MB |
| Exclave bundle layout | `ipsw fw exclave --remote "$URL" --info` (both bundles are fetched whole) | ~50 MB |
| Which IM4Ps are encrypted (keybags) | `ipsw extract --remote --kbag "$URL"` (reads IM4P headers) | small |
| Trust caches | `ipsw fw tc --remote --json "$URL"` | ~120 KB |
| dyld_shared_cache | `ipsw extract --dyld --dyld-arch arm64e --remote "$URL"` | several GB |
| Filesystem files (ipsw 3.1.750+) | `ipsw extract --remote --files --ranged --pattern '^/<path regex>' "$URL"` | the matching files and some APFS metadata |
| Whole IPSW (restore, full diff, filesystem scans) | `ipsw download ipsw ...` | 10–15 GB |

## Find a firmware URL

Both sources print URLs with `--urls` instead of downloading.

```bash
# AppleDB: every OS (iOS, iPadOS, macOS, watchOS, tvOS, visionOS, ...), betas, OTAs, RSRs
ipsw download appledb --os iOS --device "$DEVICE" --latest --release --urls
ipsw download appledb --os iOS --device "$DEVICE" --latest --beta --urls
ipsw download appledb --os macOS --device Mac17,6 --build 26A428 --urls
ipsw download appledb --os iOS --device "$DEVICE" --latest --type ota --urls

# ipsw.me: signed public iOS/iPadOS IPSWs, no local checkout needed
ipsw download ipsw --device "$DEVICE" --latest --urls
ipsw download ipsw --device "$DEVICE" --show-latest-version
```

- `--latest` means the newest build on any channel, which is often a beta. Add `--release`,
  `--beta`, or `--rc` to choose.
- `dl` is an alias for `download` and `db` for `appledb`.
- The first `download appledb` clones the AppleDB git repository (about 600 MB) into
  `~/.config/ipsw/appledb`, and each later run `git pull`s it. `--no-update` queries the existing
  checkout offline, which is also required when that directory is not writable. `--api` uses the
  GitHub API instead, which rate-limits quickly without a token.

AppleDB also returns size and SHA-256, which you can use to verify a download:

```bash
ipsw download appledb --os iOS --device "$DEVICE" --version 27.0 --release --json --no-update \
  | jq -r '.releases[].artifacts[] | "\(.size)\t\(.sha256)\t\(.active_url)"'
```

URLs feed straight into remote commands:

```bash
URL="$(ipsw download appledb --os iOS --device "$DEVICE" --latest --release --urls | head -1)"
ipsw info --remote "$URL"
ipsw fw exclave --remote "$URL" --info
```

## Read a remote IPSW or OTA without downloading it

```bash
ipsw info --remote "$URL"                              # --json for scripting
ipsw info --remote --list "$URL"                       # every member with its size
ipsw extract --kernel --remote -o ./fw/ "$URL"
ipsw extract --remote --exclave --sptm --sep -o ./fw/ "$URL"
ipsw extract --remote --pattern 'BuildManifest\.plist$' -o ./fw/ "$URL"   # any zip member by regex
ipsw extract --remote --kbag -o ./fw/ "$URL"           # keybags: which IM4Ps are still encrypted
ipsw download ipsw --device "$DEVICE" --latest --kernel -o ./fw/   # same idea, found by device
ipsw download appledb --os iOS --device "$DEVICE" --version 27.0 --release --no-update --confirm \
  --pattern 'Firmware/all_flash/DeviceTree\..*\.im4p$' -o ./fw/   # look up and range-fetch in one step
```

`--pattern` on `download ipsw/appledb/ota` fetches only the zip entries whose paths match;
`--confirm` answers the "Continue?" prompt when several files match. `--sys-ver` is rejected
with `--remote`; read the version from `info --remote` instead.

Files inside the filesystem image, as opposed to zip members, come out of a remote IPSW with
`--ranged` (ipsw 3.1.750 and later). It reads APFS through HTTP ranges and never downloads or
mounts the DMG:

```bash
ipsw extract --remote --files --ranged -o ./fw/ "$URL" \
  --pattern '^/System/Library/CoreServices/SystemVersion\.plist$'
ipsw extract --remote --files --ranged --device VirtualMac2,1 -o ./fw/ "$URL" \
  --pattern '^/System/(Library|iOSSupport/System/Library)/(PrivateFrameworks|AccessibilityBundles)/(Chat|IM).*\.loctable$'
  # a universal macOS IPSW: --device picks one of its SystemOS images
```

`--ranged` needs `--remote` and `--files`, and cannot be combined with component flags such as
`--kernel` or `--dyld`. `--ranged-dmg` picks the image: `fs` (default), `sys`, `app`, or `exc`.
Keep `--device` when the IPSW has several device-specific SystemOS images. Anchor `--pattern`
with `^/` so ipsw can skip unrelated directories. Unsupported layouts (deflated DMGs, HFS+,
legacy encrypted DMGs, sparse files) fail with an error rather than falling back to a full
download; for those, drop `--ranged` and extract from the whole image.

`extract --json` prints what it wrote, so commands can chain. Add `--json-format artifacts` for
one versioned document (`{"schema_version":1,"complete":true,"artifacts":[{"kind","path","devices"}]}`);
plain `--json` keeps the per-component shapes (`--kernel` prints `{"<path>": ["<device>", ...]}`,
`--sptm` and `--pattern` print `["<path>", ...]`).

```bash
KC="$(ipsw extract --remote --kernel --json --json-format artifacts -o ./fw/ "$URL" \
  | jq -r '.artifacts[] | select(.kind=="kernel") | .path' | head -1)"
ipsw kernel version "$KC"
```

`--device` applies only with `--kernel`, `--dyld`, `--dmg`, `--files`, or `--fcs-key`.

To read a manifest or plist, `ipsw plist <file> | jq` converts it to JSON:

```bash
ipsw plist ./fw/<BUILD>__<DEVICE>/BuildManifest.plist --no-color \
  | jq -r '.BuildIdentities[0].Manifest | to_entries[] | "\(.key)\t\(.value.Info.Path // "-")"'
```

## Download

Downloads resume by default (`--restart-all` forces a fresh start). Pass `-y`/`--confirm` so the
command does not stop at a confirmation prompt.

```bash
ipsw download ipsw --device "$DEVICE" --latest -y -o ./ipsws/
ipsw download ipsw --device "$DEVICE" --version 26.4 -y
ipsw download appledb --os iOS --device "$DEVICE" --build <BUILD> -y
ipsw download ota --platform ios --device "$DEVICE" --latest -y          # --platform is required
ipsw download ota --platform ios --device "$DEVICE" --latest --urls
ipsw download ota --platform ios --device "$DEVICE" --latest --json \
  | jq -c '.otas[] | {version, build, delivery, download_size, channel: .channel.kind}'
ipsw download macos --list
ipsw download macos --latest -y
```

`download ota --kernel/--dyld` (remote extraction) refuses AEA-encrypted OTAs (URLs ending in
`.aea`): use the IPSW with `--remote`, or download the OTA and use `ipsw ota`
(see `firmware.md`). ipsw names downloaded AEA OTAs `..._KEY_[<base64>]_<id>.aea`: the
filename carries the decryption key, so keep it intact.

## Extract from a local IPSW or OTA

```bash
ipsw extract --kernel -o ./extracted/ "$IPSW"
ipsw extract --dyld --dyld-arch arm64e -o ./extracted/ "$IPSW"   # without --dyld-arch: every arch
ipsw extract --kernel --sep --iboot --dtree --exclave --sptm -o ./extracted/ "$IPSW"
ipsw extract --files --pattern '.*/Info\.plist$' -o ./extracted/ "$IPSW"
ipsw extract --dmg fs -o ./extracted/ "$IPSW"                   # a whole DMG: app, sys, fs, exc, rdisk, rosetta
ipsw extract --sys-ver "$IPSW"
ipsw extract --kernel --json -o ./extracted/ "$IPSW"            # print extracted paths as JSON
```

Universal macOS IPSWs carry several kernelcaches and SystemOS images; pick one with
`--device <product-type|board>` (for example `--device Mac17,6`).

## Encrypted (AEA) images

DMGs and OTAs whose names end in `.aea` are AEA1-encrypted. Keys come from Apple's metadata:

```bash
ipsw extract --remote --fcs-key -o ./keys/ "$URL"                            # PEM(s) for an IPSW's AEA DMGs
ipsw download ipsw --device "$DEVICE" --latest --fcs-keys-json -o ./keys/   # PEM DB for --pem-db
ipsw download ota --platform ios --device "$DEVICE" --latest --fcs-keys      # merges into ./ota_fcs_keys.json, for --key-db
```

| Command | Key flags |
|---------|-----------|
| `extract`, `mount`, `ent`, `symbolicate` | `--pem-db` |
| `diff`, `dtree` | `--key-db`, `--key-val` |
| `fw aea` | `--key-val`, `--pem`, `--pem-db` |
| `info` | none |

See `firmware.md` for `fw aea`.

## Other sources

```bash
ipsw download kdk --host -o ./kdks/                    # Kernel Development Kit for this Mac's build
ipsw download kdk --build <BUILD> --install
ipsw download git --product xnu --latest               # Apple open-source tarballs (--json for URLs)
ipsw download rss --json | jq -r '.channel.items[] | "\(.title)\t\(.pub_date)"'   # Apple releases feed
ipsw download tss --device "$DEVICE" --latest --signed          # is this build still signed?
ipsw download tss --device "$DEVICE" --build <BUILD> --ecid <ECID> -o blob.shsh   # save a blob
ipsw download pcc --latest --urls                      # Private Cloud Compute release and asset URLs
ipsw download keys --device "$DEVICE" --build <BUILD>  # legacy firmware keys (theapplewiki)
```

- `download tss --signed` exits 0 when the build is signed and 1 when it is not (or the check
  fails); it saves nothing without `--output`. It refreshes the AppleDB checkout first;
  `--no-update` skips that (the signing check itself still needs the network).
- `download kdk` without `--host`, `--build`, `--latest`, or `--all` opens a picker, which fails
  without a terminal.
- `download git` needs a GitHub token (`--api`, then `GITHUB_TOKEN`, then `GITHUB_API_TOKEN`);
  name the product with `--product`.
- `download pcc` without `--latest`/an index plus `--urls`/`--info` opens a picker. Its `OS`
  asset URL works with `info --remote` and `extract --remote --kernel --device <ComputeModule…>`.

Version-specific differences (exit codes, prompts) in 3.1.725 and earlier are listed in SKILL.md
under "Older releases".

## Device identifiers

```bash
ipsw device-list --json | jq -r '.[] | "\(.product_type)\t\(.target)\t\(.platform)"'
ipsw device-info --prod iPhone18,1       # one device
ipsw device-info --cpid 0x8160 --json    # by chip ID
ipsw info --json "$IPSW" | jq -c '.devices[] | {product, board, cpu}'   # devices an IPSW covers
```

## Configuration

Settings live in `~/.config/ipsw/config.yaml`, keyed by command path (for example
`download.ipsw.output`, `download.ipsw.proxy`); any flag can be set there.
