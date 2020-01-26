---
title: "completion"
date: 2020-01-26T11:05:13-05:00
draft: false
weight: 100
summary: Generate bash/zsh completions.
---

### Add **zsh** completions

#### Option 1)

Pick a folder in your `$fpath` to write the completion to.

⚠️ **NOTE:** I'm using `/usr/local/share/zsh-completions`

```bash
$ ipsw completion zsh > /usr/local/share/zsh-completions/_ipsw
$ rm -f ~/.zcompdump; compinit
```

#### Option 2)

Add the following to your `~/.zshrc`

```bash
autoload -Uz compinit && compinit -C
source <(ipsw completion zsh)
compdef _ipsw ipsw
```
