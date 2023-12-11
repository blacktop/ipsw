---
id: watch
title: watch
hide_title: true
hide_table_of_contents: true
sidebar_label: watch
description: Watch Github Commits
---
## ipsw watch

Watch Github Commits

```
ipsw watch <ORG/REPO> [flags]
```

### Options

```
  -a, --api string             Github API Token
  -b, --branch string          Repo branch to watch (default "main")
  -d, --days int               Days back to search for commits (default 1)
      --discord-id string      Discord Webhook ID
      --discord-token string   Discord Webhook Token
  -f, --file string            Commit file path to watch
  -h, --help                   help for watch
      --json                   Output downloadable tar.gz URLs as JSON
  -p, --pattern string         Commit message pattern to match
  -t, --timeout duration       Timeout for watch attempts (default: 0s = no timeout/run once)
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

