package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	"github.com/blacktop/ipsw/pkg/crashlog"
	"github.com/spf13/viper"
)

// apiTokenViper mirrors initConfig's env contract (prefix + "-"/"." replacer +
// AutomaticEnv) on a throwaway instance bound to the real --api-token flag.
func apiTokenViper(t *testing.T) *viper.Viper {
	t.Helper()
	flag := symbolicateCmd.Flags().Lookup("api-token")
	if flag == nil {
		t.Fatal("symbolicate is missing the --api-token flag")
	}
	if flag.Shorthand != "t" {
		t.Fatalf("--api-token shorthand = %q, want %q", flag.Shorthand, "t")
	}
	v := viper.New()
	v.SetEnvPrefix("ipsw")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()
	v.SetConfigType("yaml")
	if err := v.BindPFlag("symbolicate.api-token", flag); err != nil {
		t.Fatalf("BindPFlag: %v", err)
	}
	return v
}

func TestAPITokenDefaultsToUnauthenticated(t *testing.T) {
	if got := apiTokenViper(t).GetString("symbolicate.api-token"); got != "" {
		t.Errorf("default token = %q, want empty (unauthenticated)", got)
	}
}

func TestAPITokenFromConfigFile(t *testing.T) {
	v := apiTokenViper(t)
	if err := v.ReadConfig(strings.NewReader("symbolicate:\n  api-token: from-config\n")); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if got := v.GetString("symbolicate.api-token"); got != "from-config" {
		t.Errorf("token = %q, want %q", got, "from-config")
	}
}

func TestAPITokenEnvOverridesConfigFile(t *testing.T) {
	t.Setenv("IPSW_SYMBOLICATE_API_TOKEN", "from-env")
	v := apiTokenViper(t)
	if err := v.ReadConfig(strings.NewReader("symbolicate:\n  api-token: from-config\n")); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if got := v.GetString("symbolicate.api-token"); got != "from-env" {
		t.Errorf("token = %q, want %q", got, "from-env")
	}
}

func TestAPITokenFlagOverridesEnv(t *testing.T) {
	t.Setenv("IPSW_SYMBOLICATE_API_TOKEN", "from-env")
	flag := symbolicateCmd.Flags().Lookup("api-token")
	v := apiTokenViper(t)
	if err := symbolicateCmd.Flags().Set("api-token", "from-flag"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	t.Cleanup(func() {
		_ = flag.Value.Set("")
		flag.Changed = false
	})
	if got := v.GetString("symbolicate.api-token"); got != "from-flag" {
		t.Errorf("token = %q, want %q", got, "from-flag")
	}
}

// TestExpandSettingsNeverRendersAPIToken pins the config-expansion carve-out:
// a token that looks like a path must be left alone and must never be logged.
func TestExpandSettingsNeverRendersAPIToken(t *testing.T) {
	const token = "~/looks-like-a-path-Zx9q7Kv2Ln"

	h := memory.New()
	logger, ok := log.Log.(*log.Logger)
	if !ok {
		t.Fatal("apex logger has an unexpected implementation")
	}
	previousHandler := logger.Handler
	log.SetHandler(h)
	t.Cleanup(func() { log.SetHandler(previousHandler) })

	settings := map[string]any{
		"symbolicate": map[string]any{
			"api-token":  token,
			"signatures": "~/sigs", // control: ordinary paths still expand
		},
	}
	expandSettings(settings, "", false)

	sym := settings["symbolicate"].(map[string]any)
	if sym["api-token"] != token {
		t.Errorf("token was rewritten: %q", sym["api-token"])
	}
	if sym["signatures"] == "~/sigs" {
		t.Error("control path was not expanded; the carve-out may be too broad")
	}
	// The control key must have produced an expansion warning, otherwise the
	// leak check below would pass vacuously on an empty log.
	if len(h.Entries) == 0 {
		t.Fatal("no log entries captured; the leak check would be vacuous")
	}
	for _, e := range h.Entries {
		if strings.Contains(e.Message, token) {
			t.Errorf("token leaked into a log line: %s", e.Message)
		}
		for k, val := range e.Fields {
			if s, ok := val.(string); ok && strings.Contains(s, token) {
				t.Errorf("token leaked into log field %s: %s", k, s)
			}
		}
	}
}

// newAPITokenProbeServer records Authorization headers and answers _ping with 200
// and everything else with 404, so symbolication stops right after the two
// requests it takes to prove the credential is attached.
func newAPITokenProbeServer(t *testing.T) (*httptest.Server, *[][]string) {
	t.Helper()
	var auths [][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.Header.Values("Authorization"))
		if r.URL.Path == "/v1/_ping" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv, &auths
}

func TestSymbolicate210WithDatabaseTokenSendsBearer(t *testing.T) {
	const token = "sYnth3t1c.T0ken_VALUE-123"
	srv, auths := newAPITokenProbeServer(t)

	if err := (&crashlog.Ips{}).Symbolicate210WithDatabaseToken(srv.URL, token); err == nil {
		t.Fatal("want the mock's not-found error, got nil")
	}
	if len(*auths) == 0 {
		t.Fatal("no requests reached the symbol server")
	}
	for i, auth := range *auths {
		if len(auth) != 1 || auth[0] != "Bearer "+token {
			t.Errorf("request %d: Authorization = %q, want exactly [%q]", i, auth, "Bearer "+token)
		}
	}
}

func TestSymbolicate210WithDatabaseStaysUnauthenticated(t *testing.T) {
	srv, auths := newAPITokenProbeServer(t)

	if err := (&crashlog.Ips{}).Symbolicate210WithDatabase(srv.URL); err == nil {
		t.Fatal("want the mock's not-found error, got nil")
	}
	if len(*auths) == 0 {
		t.Fatal("no requests reached the symbol server")
	}
	for i, auth := range *auths {
		if len(auth) != 0 {
			t.Errorf("request %d: sent Authorization %q, want none", i, auth)
		}
	}
}

func TestSymbolicate210WithDatabaseTokenRejectsMalformedBeforeTransport(t *testing.T) {
	const token = "bad Zx9q7Kv2Ln"
	srv, auths := newAPITokenProbeServer(t)

	err := (&crashlog.Ips{}).Symbolicate210WithDatabaseToken(srv.URL, token)
	if err == nil {
		t.Fatal("want a validation error, got nil")
	}
	if strings.Contains(err.Error(), "Zx9q7Kv2Ln") {
		t.Errorf("error leaks the token: %v", err)
	}
	if len(*auths) != 0 {
		t.Errorf("malformed token reached the service: %d requests", len(*auths))
	}
}
