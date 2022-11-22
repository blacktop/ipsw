---
id: ipsw_completion_zsh
title: ipsw completion zsh
hide_title: true
sidebar_label: zsh
description: Generate the autocompletion script for zsh
last_update:
  date: 2022-11-21T19:10:35-07:00
  author: blacktop
---
# ipsw completion zsh

Generate the autocompletion script for zsh

## Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(ipsw completion zsh); compdef _ipsw ipsw

To load completions for every new session, execute once:

### Linux:

	ipsw completion zsh > "${fpath[1]}/_ipsw"

### macOS:

	ipsw completion zsh > $(brew --prefix)/share/zsh/site-functions/_ipsw

You will need to start a new shell for this setup to take effect.


```
ipsw completion zsh [flags]
```

## Options

```
  -h, --help              help for zsh
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

