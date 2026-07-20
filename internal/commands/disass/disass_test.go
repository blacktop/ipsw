package disass

import "testing"

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
