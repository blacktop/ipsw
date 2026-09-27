package download

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestResolveGitHubToken(t *testing.T) {
	for _, tt := range []struct {
		name, configured, github, api, want string
	}{
		{name: "configured wins", configured: "flag-token", github: "env-token", api: "fallback-token", want: "flag-token"},
		{name: "first environment", github: "env-token", api: "fallback-token", want: "env-token"},
		{name: "empty first environment", api: "fallback-token", want: "fallback-token"},
		{name: "whitespace first environment", github: " \t", api: "fallback-token", want: "fallback-token"},
		{name: "missing"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveGitHubToken(tt.configured, func(name string) string {
				return map[string]string{"GITHUB_TOKEN": tt.github, "GITHUB_API_TOKEN": tt.api}[name]
			})
			if got != tt.want || (err != nil) != (tt.want == "") {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestDownloadGitRejectsPositionals(t *testing.T) {
	if err := downloadGitCmd.Args(downloadGitCmd, []string{"fake-product"}); err == nil || !strings.Contains(err.Error(), "--product") {
		t.Fatalf("expected actionable positional error, got %v", err)
	}
}

func TestDownloadGitMissingTokenFailsBeforeRequest(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITHUB_API_TOKEN", "")
	previous := viper.Get("download.git.api")
	viper.Set("download.git.api", "")
	t.Cleanup(func() { viper.Set("download.git.api", previous) })
	previousTransport := http.DefaultTransport
	requests := 0
	http.DefaultTransport = ipswFeedTransport(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("unexpected network request")
	})
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	if err := downloadGitCmd.RunE(downloadGitCmd, nil); err == nil || !strings.Contains(err.Error(), "GitHub GraphQL requires a token") {
		t.Fatalf("expected local authentication error, got %v", err)
	}
	if requests != 0 {
		t.Fatalf("sent %d requests without a token", requests)
	}
}
