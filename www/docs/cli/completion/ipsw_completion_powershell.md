---
id: ipsw_completion_powershell
title: ipsw completion powershell
hide_title: true
sidebar_label: powershell
description: Generate the autocompletion script for powershell
last_update:
  date: 2022-11-21T19:10:35-07:00
  author: blacktop
---
# ipsw completion powershell

Generate the autocompletion script for powershell

## Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	ipsw completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


```
ipsw completion powershell [flags]
```

## Options

```
  -h, --help              help for powershell
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

