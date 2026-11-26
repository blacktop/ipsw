# Symbolicating Crashes and Panics

## Contents
- [Get the logs](#get-the-logs)
- [Symbolicate](#symbolicate)
- [Match the firmware](#match-the-firmware)
- [From a frame to code](#from-a-frame-to-code)
- [Kernel addresses without a log](#kernel-addresses-without-a-log)

## Get the logs

From a USB-connected device (needs a trusted pairing; see `device.md`):

```bash
ipsw idev crash ls                                   # list crash logs on the device
ipsw idev crash pull <PATH_FROM_LS> -o ./crashes/    # pull specific logs
ipsw idev crash pull --all -o ./crashes/             # pull everything (--rm also deletes them from the device)
```

`idev crash pull` with neither a path nor `--all` opens an interactive picker.

On a Mac, device logs synced by Finder/Xcode live under
`~/Library/Logs/CrashReporter/MobileDevice/<device>/`; local ones under
`~/Library/Logs/DiagnosticReports/`.

## Symbolicate

`ipsw symbolicate <CRASHLOG> [IPSW|DSC]` handles `.ips` crash reports and panics (bug type 210).

```bash
ipsw symbolicate panic-full-<date>.ips "$IPSW"                 # kernel + userspace frames
ipsw symbolicate crash.ips "$DSC"                              # userspace frames from a DSC
ipsw symbolicate panic.ips                                     # falls back to Xcode DeviceSupport (userspace only)
ipsw symbolicate panic.ips "$IPSW" --peek --peek-count 10      # disassembly around each panicked frame
ipsw symbolicate panic.ips "$IPSW" --signatures symbolicator/kernel   # name frames in stripped kernels
```

| Flag | Use |
|------|-----|
| `--all` / `--running` | all threads / only running threads (default: the crashed thread) |
| `--proc <NAME>` | filter a multi-process report (panics, stackshots) |
| `--demangle`, `--hex` | Swift demangling, hex offsets |
| `--unslide` | unslide userspace frames for static analysis (kernel frames are already unslid) |
| `--kc-slide <HEX>` / `--dsc-slide <HEX>` | rebase kernel / DSC frames (for live debugging with lldb) |
| `--ida` | write an IDAPython script that marks the panic frames |
| `--extra <DIR>` | extra binaries (third-party dylibs, apps) to symbolicate against |
| `--server <URL>` | query a symbol server (`ipswd`) instead of local firmware; see below |
| `--pem-db` | AEA keys for encrypted IPSW DMGs |

### Remote symbol server

A symbol server (`ipswd start`) holds pre-indexed firmware, so a report can be symbolicated
without the IPSW on hand. A server behind authentication takes a bearer token:

```bash
ipsw symbolicate --server http://localhost:3993 panic.ips
IPSW_SYMBOLICATE_API_TOKEN="$TOKEN" ipsw symbolicate --server https://syms.example.com panic.ips
```

Supply the token through `IPSW_SYMBOLICATE_API_TOKEN` or `symbolicate: {api-token: ...}` in
`~/.config/ipsw/config.yaml` rather than `--api-token`/`-t`, so it stays out of shell history
and process listings. Tokens are only sent over HTTPS, except to a loopback address.

## Match the firmware

A report symbolicates correctly only against the exact build that produced it. The first line
of an `.ips` file is a JSON header whose `os_version` names the build (for example
`iPhone OS 26.4 (23E246)`); fetch that build:

```bash
head -1 panic.ips | jq -r .os_version
URL="$(ipsw download appledb --os iOS --device "$DEVICE" --build <BUILD> --urls | head -1)"
ipsw extract --kernel --remote -o ./fw/ "$URL"
```

`--force` symbolicates against a mismatched IPSW (useful for virtual devices); treat the
results as approximate.

## From a frame to code

```bash
ipsw dyld a2s "$DSC" <UNSLID_ADDR>                     # confirm the symbol for a userspace frame
ipsw dyld disass "$DSC" --vaddr <UNSLID_ADDR> --count 40
ipsw macho disass "$KC" --fileset-entry com.apple.kernel --vaddr <KERNEL_ADDR> --count 40
```

Use `--unslide` output (userspace) or the kernel frame addresses as printed; they match static
disassembly.

## Kernel addresses without a log

```bash
mkdir -p ./syms && ipsw kernel symbolicate --signatures symbolicator/kernel --json -o ./syms/ "$KC"
ipsw kernel symbolicate --lookup 0xfffffe000ab90040 ./syms/<KC_NAME>.symbols.json
```

See `kernel.md` for the signatures repository.
