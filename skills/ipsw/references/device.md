# USB-Connected Devices (`ipsw idev`)

`ipsw idev` talks to a paired, trusted iPhone/iPad over USB (lockdown services). Pass
`--udid <UDID>` when more than one device is connected. Commands that change the device
(install, uninstall, restore, profile, erase-style operations) need the user's explicit go-ahead.

## Contents
- [Identify](#identify)
- [Logs and crashes](#logs-and-crashes)
- [Processes, apps, and I/O Registry](#processes-apps-and-io-registry)
- [Files](#files)
- [Developer disk image and symbols](#developer-disk-image-and-symbols)
- [Other commands](#other-commands)

## Identify

```bash
ipsw idev list                 # connected devices (--json)
ipsw idev list --ipsw          # names in the product-type form ipsw's download commands take
```

## Logs and crashes

```bash
ipsw idev syslog -t 30                           # streams until killed: always pass a timeout
ipsw idev crash ls
ipsw idev crash pull <PATH_FROM_LS> -o ./crashes/     # or --all; no argument opens a picker
```

Symbolicate pulled logs with `ipsw symbolicate` (see `symbolication.md`).

## Processes, apps, and I/O Registry

```bash
ipsw idev ps --json                              # running processes
ipsw idev apps ls --json                         # --system, --user, --hidden to filter
ipsw idev diag ioreg --plane IOService           # I/O Registry (also --class, --name)
ipsw idev diag info                              # device diagnostics summary
```

## Files

```bash
ipsw idev afc ls                                  # the media partition (DCIM, Downloads, ...)
ipsw idev afc tree
ipsw idev afc pull /Downloads/file.bin ./file.bin  # <remote path> <local path>
```

AFC sees only the media partition, not the system filesystem.

## Developer disk image and symbols

```bash
ipsw idev img ddi --info                         # personalized DDI status
ipsw idev img ls                                 # mounted images
ipsw idev fsyms -o ./device-symbols/             # pull the device's dyld_shared_cache and linker
```

`fsyms` gives you the exact DSC the device is running, which matches its crash logs.

## Other commands

| Command | Does |
|---------|------|
| `idev screen -o ./shots/` | screenshot |
| `idev pcap` | capture network traffic |
| `idev noti` | observe Darwin notifications |
| `idev proxy` | TCP proxy to a device port (ssh, debugserver) |
| `idev loc set` / `loc play` | simulate location |
| `idev prof ls` / `prov ls` | configuration / provisioning profiles |
| `idev restore enter` / `exit` | recovery mode (changes device state) |

Run `ipsw idev <cmd> --help` for flags; many commands stream until interrupted.
