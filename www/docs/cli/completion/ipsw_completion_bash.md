---
id: ipsw_completion_bash
title: ipsw completion bash
hide_title: true
sidebar_label: bash
description: Generate the autocompletion script for bash
last_update:
  date: 2022-11-23T16:33:46-07:00
  author: blacktop
---
# ipsw completion bash

Generate the autocompletion script for bash

## Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(ipsw completion bash)

To load completions for every new session, execute once:

### Linux:

	ipsw completion bash > /etc/bash_completion.d/ipsw

### macOS:

	ipsw completion bash > $(brew --prefix)/etc/bash_completion.d/ipsw

You will need to start a new shell for this setup to take effect.


```
ipsw completion bash
```

## Options

```
  -h, --help              help for bash
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

