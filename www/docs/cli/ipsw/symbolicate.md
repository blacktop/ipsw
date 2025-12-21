---
id: symbolicate
title: symbolicate
hide_title: true
hide_table_of_contents: true
sidebar_label: symbolicate
description: Symbolicate ARM 64-bit crash logs (similar to Apple's symbolicatecrash)
---
## ipsw symbolicate

Symbolicate ARM 64-bit crash logs (similar to Apple's symbolicatecrash)

```
ipsw symbolicate <CRASHLOG> [IPSW|DSC] [flags]
```

### Examples

```bash
# Symbolicate a panic crashlog (BugType=210) with an IPSW
❯ ipsw symbolicate panic-full-2024-03-21-004704.000.ips iPad_Pro_HFR_17.4_21E219_Restore.ipsw

# Show disassembly around panic frames with --peek (default 5 instructions)
❯ ipsw symbolicate panic.ips firmware.ipsw --peek

# Show more instructions around panic frames (10 instructions, centered on frame)
❯ ipsw symbolicate panic.ips firmware.ipsw --peek --peek-count 10
  # Note: If frame is at function start, extra instructions shift to after the frame

# Unslide user-space addresses for static analysis (kernel frames are always unslid)
❯ ipsw symbolicate panic.ips firmware.ipsw --unslide
  # Note: Kernel frame addresses are already KASLR-unslid and match static disassemblers
  # The --unslide flag only affects user-space frames (processes like launchd, SpringBoard, etc.)

# Apply custom KASLR slide to kernelcache frames for lldb live debugging
❯ ipsw symbolicate panic.ips firmware.ipsw --kc-slide 0x14f74000
  # Useful when reproducing a crash with a different KASLR slide
  # Shows runtime addresses you can use with lldb breakpoints

# Apply custom slide to dyld_shared_cache frames for lldb live debugging
❯ ipsw symbolicate panic.ips firmware.ipsw --dsc-slide 0x1a000000
  # For debugging user-space crashes where DSC was loaded at a different address

# Combine both slides for full runtime address mapping
❯ ipsw symbolicate panic.ips firmware.ipsw --kc-slide 0x14f74000 --dsc-slide 0x1a000000

# Generate IDAPython script to mark panic frames in IDA Pro
❯ ipsw symbolicate panic.ips firmware.ipsw --ida
  # Outputs panic.ips.kc.ida.py for kernel frames (load in IDA with kernelcache)
  # Outputs panic.ips.dsc.ida.py for DSC frames if present (load in IDA with DSC image)

# Pretty print a crashlog (BugType=309) these are usually symbolicated by the OS
❯ ipsw symbolicate --color Delta-2024-04-20-135807.ips

# Symbolicate an old style crashlog (BugType=109) requiring a dyld_shared_cache
❯ ipsw symbolicate Delta-2024-04-20-135807.ips dyld_shared_cache
  ⨯ please supply a dyld_shared_cache for iPhone13,3 running 14.5 (18E5154f)
```

### Options

```
  -a, --all                 Show all threads in crashlog
  -d, --demangle            Demangle symbol names
      --dsc-slide string    Apply custom slide to dyld_shared_cache frames for live debugging (hex, e.g. 0x1a000000)
  -x, --extra string        Path to folder with extra files for symbolication
  -h, --help                help for symbolicate
      --hex                 Display function offsets in hexadecimal
      --ida                 Generate IDAPython script to mark panic frames in IDA Pro
      --kc-slide string     Apply custom KASLR slide to kernelcache frames for live debugging (hex, e.g. 0x14f74000)
      --peek                Show disassembly instructions around each panicked frame
      --peek-count int      Number of instructions to show with --peek (centered on frame, respects function boundaries) (default 5)
      --pem-db string       AEA pem DB JSON file
  -p, --proc string         Filter crashlog by process name
  -r, --running             Show all running (TH_RUN) threads in crashlog
  -s, --server string       Symbol Server DB URL
      --signatures string   Path to signatures folder
  -u, --unslide             Unslide user-space addresses for static analysis (kernel frames are always unslid)
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw](/docs/cli/ipsw)	 - Download and Parse IPSWs (and SO much more)

