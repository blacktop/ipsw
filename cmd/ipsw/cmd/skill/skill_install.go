/*
Copyright © 2018-2026 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package skill

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/skills"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	agentAgents = "agents"
	agentClaude = "claude"
)

func init() {
	SkillCmd.AddCommand(skillInstallCmd)

	skillInstallCmd.Flags().StringP("agent", "a", agentAgents,
		"Agent whose skills directory to install into (agents, claude)")
	skillInstallCmd.Flags().BoolP("local", "l", false,
		"Install into the current folder instead of your home directory")
	cobra.CheckErr(skillInstallCmd.RegisterFlagCompletionFunc("agent",
		cobra.FixedCompletions([]string{agentAgents, agentClaude}, cobra.ShellCompDirectiveNoFileComp)))

	cobra.CheckErr(viper.BindPFlag("skill.install.agent", skillInstallCmd.Flags().Lookup("agent")))
	cobra.CheckErr(viper.BindPFlag("skill.install.local", skillInstallCmd.Flags().Lookup("local")))
}

// skillInstallCmd represents the skill install command
var skillInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the ipsw agent skill",
	Long: heredoc.Doc(`
		Install the ipsw agent skill bundled with this binary.

		By default the skill is written to ~/.agents/skills/ipsw, where Codex and other agents
		that follow the .agents/skills convention look for skills. Use --agent claude for
		Claude Code (~/.claude/skills/ipsw, or $CLAUDE_CONFIG_DIR/skills/ipsw when set).

		With --local the skill goes into the current folder (./.agents/skills/ipsw or
		./.claude/skills/ipsw) so it applies only to that project.

		Re-run after upgrading ipsw to refresh the skill; an existing copy is replaced. If you
		also installed the skill as a Claude Code or Codex plugin, the agent loads it twice.
	`),
	Example: heredoc.Doc(`
		# Install for Codex and other agents that read ~/.agents/skills
		❯ ipsw skill install

		# Install for Claude Code
		❯ ipsw skill install --agent claude

		# Install into the current project for Claude Code
		❯ ipsw skill install --agent claude --local`),
	Args:          cobra.NoArgs,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		agent := viper.GetString("skill.install.agent")
		local := viper.GetBool("skill.install.local")
		skillsDir, err := resolveSkillsDir(agent, local)
		if err != nil {
			return err
		}
		version, err := skills.Version()
		if err != nil {
			return err
		}
		dest, err := skills.Install(skillsDir)
		if err != nil {
			return err
		}
		log.Infof("Installed ipsw skill v%s to %s", version, dest)
		return nil
	},
}

func resolveSkillsDir(agent string, local bool) (string, error) {
	var configDir string
	switch agent {
	case agentAgents:
		configDir = ".agents"
	case agentClaude:
		if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" && !local {
			return filepath.Join(dir, "skills"), nil
		}
		configDir = ".claude"
	default:
		return "", fmt.Errorf("unknown --agent %q: use %q or %q", agent, agentAgents, agentClaude)
	}
	if local {
		dir, err := filepath.Abs(filepath.Join(configDir, "skills"))
		if err != nil {
			return "", fmt.Errorf("failed to resolve the current folder: %w", err)
		}
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to find your home directory (try --local): %w", err)
	}
	return filepath.Join(home, configDir, "skills"), nil
}
