package skill

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveSkillsDir(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	claudeConfig := filepath.Join(t.TempDir(), "claude-config")
	t.Setenv("HOME", home)
	t.Chdir(cwd)
	// t.TempDir may sit behind a symlink (macOS /var -> /private/var); compare against the
	// working directory as the process sees it.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		agent        string
		local        bool
		claudeConfig string
		want         string
	}{
		{"default home", agentAgents, false, "", filepath.Join(home, ".agents", "skills")},
		{"default local", agentAgents, true, "", filepath.Join(cwd, ".agents", "skills")},
		{"claude home", agentClaude, false, "", filepath.Join(home, ".claude", "skills")},
		{"claude config dir", agentClaude, false, claudeConfig, filepath.Join(claudeConfig, "skills")},
		{"claude local ignores config dir", agentClaude, true, claudeConfig,
			filepath.Join(cwd, ".claude", "skills")},
		{"agents ignores claude config dir", agentAgents, false, claudeConfig,
			filepath.Join(home, ".agents", "skills")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CLAUDE_CONFIG_DIR", tt.claudeConfig)
			got, err := resolveSkillsDir(tt.agent, tt.local)
			if err != nil {
				t.Fatalf("resolveSkillsDir(%q, %v) error: %v", tt.agent, tt.local, err)
			}
			if got != tt.want {
				t.Errorf("resolveSkillsDir(%q, %v) = %q, want %q", tt.agent, tt.local, got, tt.want)
			}
		})
	}
}

func TestResolveSkillsDirRejectsUnknownAgent(t *testing.T) {
	for _, agent := range []string{"", "codex", "Claude"} {
		_, err := resolveSkillsDir(agent, false)
		if err == nil || !strings.Contains(err.Error(), "unknown --agent") {
			t.Errorf("resolveSkillsDir(%q) error = %v, want unknown --agent", agent, err)
		}
	}
}

func TestInstallCommandWritesSkill(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")

	SkillCmd.SetArgs([]string{"install", "--agent", agentClaude})
	if err := SkillCmd.Execute(); err != nil {
		t.Fatalf("ipsw skill install --agent claude: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "skills", "ipsw", "SKILL.md")); err != nil {
		t.Errorf("SKILL.md not installed: %v", err)
	}
}
