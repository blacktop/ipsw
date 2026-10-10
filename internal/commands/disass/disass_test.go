package disass

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestFlagWasProvidedByEnvironmentAtDefault(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().Float64("dec-temp", 0.2, "")
	t.Setenv("IPSW_MACHO_DISASS_DEC_TEMP", "0.2")
	if !FlagWasProvided(cmd, "dec-temp", "macho.disass.dec-temp") {
		t.Fatal("an environment value equal to the default is still explicit")
	}
}

func TestReusableModel(t *testing.T) {
	models := map[string]string{
		"Claude Sonnet 5": "claude-sonnet-5",
	}

	tests := []struct {
		name     string
		provider string
		want     string
	}{
		{name: "Copilot ACP uses model ID", provider: "copilot", want: "claude-sonnet-5"},
		{name: "Claude ACP uses model ID", provider: "claude", want: "claude-sonnet-5"},
		{name: "OpenAI API uses display key", provider: "openai", want: "Claude Sonnet 5"},
		{name: "OpenRouter API uses display key", provider: "openrouter", want: "Claude Sonnet 5"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := reusableModel(test.provider, models, "Claude Sonnet 5"); got != test.want {
				t.Fatalf("reusableModel() = %q, want %q", got, test.want)
			}
		})
	}
}
