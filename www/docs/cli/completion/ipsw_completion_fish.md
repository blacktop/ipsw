---
id: ipsw_completion_fish
title: ipsw completion fish
hide_title: true
sidebar_label: fish
description: Generate the autocompletion script for fish
last_update:
  date: 2022-11-21T19:10:35-07:00
  author: blacktop
---
# ipsw completion fish

Generate the autocompletion script for fish

## Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	ipsw completion fish | source

To load completions for every new session, execute once:

	ipsw completion fish > ~/.config/fish/completions/ipsw.fish

You will need to start a new shell for this setup to take effect.


```
ipsw completion fish [flags]
```

## Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
```

## Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

## See also

* [ipsw completion](/docs/cli/completion/ipsw_completion)	 - Generate the autocompletion script for the specified shell

