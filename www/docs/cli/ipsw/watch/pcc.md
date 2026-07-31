---
id: pcc
title: pcc
hide_title: true
hide_table_of_contents: true
sidebar_label: pcc
description: Watch for new PCC vphone600 firmware
---
## ipsw watch pcc

Watch for new PCC vphone600 firmware

```
ipsw watch pcc [flags]
```

### Examples

```bash
# Watch for new vphone600 firmware and print notifications
❯ ipsw watch pcc

# Announce new vphone600 firmware to Discord
❯ IPSW_WATCH_DISCORD_ID=1234 IPSW_WATCH_DISCORD_TOKEN=SECRET ipsw watch pcc --discord --interval 5m

# Initialize state and notify for existing vphone600 releases
❯ ipsw watch pcc --notify-initial --interval 0

```

### Options

```
  -h, --help                help for pcc
      --insecure            Do not verify TLS certificates
  -t, --interval duration   Polling interval (0 runs once) (default 5m0s)
      --notify-initial      Notify for existing vphone600 releases when creating state
      --proxy string        HTTP/HTTPS proxy
      --state string        Path to durable PCC watcher state
```

### Options inherited from parent commands

```
      --color                  colorize output
      --config string          config file (default is $HOME/.config/ipsw/config.yaml)
      --discord                Announce to Discord
      --discord-icon string    Discord Post Icon URL
      --discord-id string      Discord Webhook ID
      --discord-token string   Discord Webhook Token
      --no-color               disable colorize output
  -V, --verbose                verbose output
```

### SEE ALSO

* [ipsw watch](/docs/cli/ipsw/watch)	 - Watch repositories and firmware releases

