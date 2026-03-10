---
id: cpp
title: cpp
hide_title: true
hide_table_of_contents: true
sidebar_label: cpp
description: Discover C++ classes from kernelcache
---
## ipsw kernel cpp

Discover C++ classes from kernelcache

```
ipsw kernel cpp <kernelcache> [flags]
```

### Examples

```bash
# Discover all classes
❯ ipsw kernel cpp kernelcache.release.iPhone17,1
# Show specific class
❯ ipsw kernel cpp -c IOService kernelcache.release.iPhone17,1
# Scan only the kernel entry
❯ ipsw kernel cpp -e com.apple.kernel kernelcache.release.iPhone17,1
# JSON output
❯ ipsw kernel cpp --json kernelcache.release.iPhone17,1
# Show inheritance hierarchy
❯ ipsw kernel cpp --inheritance kernelcache.release.iPhone17,1
# Profile CPU usage
❯ ipsw kernel cpp --cpuprofile cpu.prof kernelcache.release.iPhone17,1
```

### Options

```
  -a, --arch string             Which architecture to use for fat/universal MachO
      --blockprofile string     Write block profile to file
  -c, --class string            Only emit the specified class name
      --cpuprofile string       Write CPU profile to file
  -e, --entry stringArray       Only scan the specified bundle/entry (repeatable)
      --flightrecorder string   Write flight recorder trace to file
  -h, --help                    help for cpp
  -i, --inheritance             Show inheritance hierarchy
  -j, --json                    Output classes as JSON
  -l, --limit int               Limit number of classes to display (0 = all)
      --memprofile string       Write heap profile to file
      --mutexprofile string     Write mutex profile to file
  -o, --output string           Write output to file
      --pprof string            Serve net/http/pprof on address (e.g. localhost:6060)
      --timings                 Print timing breakdown
      --trace string            Write runtime trace to file
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw kernel](/docs/cli/ipsw/kernel)	 - Parse kernelcache

