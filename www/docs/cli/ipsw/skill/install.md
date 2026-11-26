---
id: install
title: install
hide_title: true
hide_table_of_contents: true
sidebar_label: install
description: Install the ipsw agent skill
---
## ipsw skill install

Install the ipsw agent skill

### Synopsis

Install the ipsw agent skill bundled with this binary.

By default the skill is written to ~/.agents/skills/ipsw, where Codex and other agents
that follow the .agents/skills convention look for skills. Use --agent claude for
Claude Code (~/.claude/skills/ipsw, or $CLAUDE_CONFIG_DIR/skills/ipsw when set).

With --local the skill goes into the current folder (./.agents/skills/ipsw or
./.claude/skills/ipsw) so it applies only to that project.

Re-run after upgrading ipsw to refresh the skill; an existing copy is replaced. If you
also installed the skill as a Claude Code or Codex plugin, the agent loads it twice.


```
ipsw skill install [flags]
```

### Examples

```bash
# Install for Codex and other agents that read ~/.agents/skills
❯ ipsw skill install

# Install for Claude Code
❯ ipsw skill install --agent claude

# Install into the current project for Claude Code
❯ ipsw skill install --agent claude --local
```

### Options

```
  -a, --agent string         Agent whose skills directory to install into (agents, claude) (default "agents")
  -h, --help[=true|false]    help for install
  -l, --local[=true|false]   Install into the current folder instead of your home directory
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw skill](/docs/cli/ipsw/skill)	 - Manage the ipsw agent skill bundled with this binary

