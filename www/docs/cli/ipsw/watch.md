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

### Examples

```bash
# Watch the main branch of the WebKit/WebKit repo for new commits every 5 minutes with the pattern '254930' for the last 30 days
❯ ipsw watch --pattern '254930' --days 30 WebKit/WebKit --branch main --timeout 5m
# Watch the main branch of the WebKit/WebKit repo for new commits every 5 minutes and announce to Discord
❯ IPSW_WATCH_DISCORD_ID=1234 IPSW_WATCH_DISCORD_TOKEN=SECRET ipsw watch --pattern 'Lockdown Mode' --days 1 --timeout 5m WebKit/WebKit
# Watch the main branch of the WebKit/WebKit repo for new commits every 5 minutes and run a command on new commits
# NOTE: the command will have access to the following environment variables:
#   - IPSW_WATCH_OID
#   - IPSW_WATCH_URL
#   - IPSW_WATCH_AUTHOR
#   - IPSW_WATCH_DATE
#   - IPSW_WATCH_MESSAGE
❯ ipsw watch WebKit/WebKit --command 'echo "New Commit: $IPSW_WATCH_URL"'
# Watch WebKit/WebKit for new tags every 5 minutes and announce to Discord
❯ IPSW_WATCH_DISCORD_ID=1234 IPSW_WATCH_DISCORD_TOKEN=SECRET ipsw watch WebKit/WebKit --tags --timeout 5m
```

### Options

```
  -a, --api string                      Github API Token
  -b, --branch string                   Repo branch to watch (default "main")
      --cache string                    Cache file to store seen commits/tags
  -c, --command string                  Command to run on new commit
  -d, --days int                        Days back to search for commits (default 1)
      --discord                         Annouce to Discord
      --discord-icon string             Discord Post Icon URL
      --discord-id string               Discord Webhook ID
      --discord-token string            Discord Webhook Token
  -f, --file string                     Commit file path to watch
  -h, --help                            help for watch
      --json                            Output downloadable tar.gz URLs as JSON
      --mastodon                        Annouce to Mastodon
      --mastodon-access-token string    Mastodon Access Token
      --mastodon-client-id string       Mastodon Client ID
      --mastodon-client-secret string   Mastodon Client Secret
      --mastodon-server string          Mastodon Server URL (default "https://mastodon.social")
  -p, --pattern string                  Commit message pattern to match
      --post                            Create social media post for NEW tags
  -g, --tags                            Watch for new tags
  -t, --timeout duration                Timeout for watch attempts (default: 0s = no timeout/run once)
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

