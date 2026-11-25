---
id: security
title: security
hide_title: true
hide_table_of_contents: true
sidebar_label: security
description: Watch Apple security advisories for new and changed CVEs
---
## ipsw watch security

Watch Apple security advisories for new and changed CVEs

### Synopsis

Watch Apple security advisories for new and changed CVEs.

Reads the security releases table at https://support.apple.com/en-us/100100 and the
CSAF JSON Apple publishes for advisories released on or after 2026-09-14. Apple edits
advisories after release, so every poll re-reads each one (with conditional requests)
and reports CVEs added or removed and changed credits, fixed products, impact or
description. Requests are spaced 3s apart and HTTP 429 responses are retried with backoff.


```
ipsw watch security [flags]
```

### Examples

```bash
# Create state silently, then report changes every hour
❯ ipsw watch security

# One-shot scan that lists every CVE credited to a researcher
❯ ipsw watch security --interval 0 --notify-initial --credit "Jane Doe" --state /tmp/sec.json

# Stream events as JSON lines for scripts and agents
❯ ipsw watch security --json --interval 30m

# Announce changes to Discord
❯ IPSW_WATCH_DISCORD_ID=1234 IPSW_WATCH_DISCORD_TOKEN=SECRET ipsw watch security --discord

```

### Options

```
      --credit stringArray            Only report CVEs credited to NAME (case-insensitive substring, repeatable)
  -h, --help[=true|false]             help for security
      --insecure[=true|false]         Do not verify TLS certificates
  -t, --interval duration             Polling interval (0 runs once) (default 1h0m0s)
      --json[=true|false]             Print one JSON event per line
      --notify-initial[=true|false]   Report existing advisories when creating state
      --proxy string                  HTTP/HTTPS proxy
      --state string                  Path to durable security watcher state
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --discord[=true|false]    Announce to Discord
      --discord-icon string     Discord Post Icon URL
      --discord-id string       Discord Webhook ID
      --discord-token string    Discord Webhook Token
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw watch](/docs/cli/ipsw/watch)	 - Watch repositories and firmware releases

