---
id: ida
title: ida
hide_title: true
hide_table_of_contents: true
sidebar_label: ida
description: 🚧 Analyze kernelcache in IDA Pro
---
## ipsw kernel ida

🚧 Analyze kernelcache in IDA Pro

```
ipsw kernel ida <KC> [KEXT] [flags]
```

### Options

```
  -c, --delete-db             Disassemble a new file (delete the old database)
      --diaphora-db string    Path to Diaphora database
  -k, --docker                Run IDA Pro in a docker container
      --docker-image string   IDA Pro docker image (default "blacktop/idapro:8.2-pro")
  -g, --enable-gui            Enable IDA Pro GUI (defaults to headless)
  -e, --extra-args strings    IDA Pro CLI extra arguments
  -h, --help                  help for ida
  -p, --ida-path string       IDA Pro directory (darwin default: /Applications/IDA Pro */ida64.app/Contents/MacOS)
  -l, --log-file string       IDA log file
  -o, --output string         Output folder
  -s, --script string         IDA Pro script to run
  -r, --script-args strings   IDA Pro script arguments
  -t, --temp-db               Do not create a database file (requires --enable-gui)
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

