package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSymbolsRunsWithoutJSONFlag(t *testing.T) {
	t.Setenv("IPSW_NO_UPDATE_CHECK", "1")
	missingIPSW := filepath.Join(t.TempDir(), "missing.ipsw")

	err := symbolsCmd.RunE(symbolsCmd, []string{missingIPSW})
	if err == nil {
		t.Fatal("expected missing file error, got nil")
	}
	if strings.Contains(err.Error(), "only JSONL output is supported") {
		t.Fatalf("symbols command still requires --json: %v", err)
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err=%v, want missing file validation after default JSONL mode", err)
	}
}

func TestSymbolsExposesOptInFactsFlag(t *testing.T) {
	flag := symbolsCmd.Flags().Lookup("facts")
	if flag == nil {
		t.Fatal("symbols command is missing --facts")
	}
	if flag.DefValue != "false" {
		t.Fatalf("--facts default = %q, want false", flag.DefValue)
	}
}

func TestSymbolsFactsBoardsRequiresFactsJSONAndNoDevice(t *testing.T) {
	flags := symbolsCmd.Flags()
	for _, tc := range []struct {
		name, facts, json, device string
	}{
		{"missing facts", "false", "true", ""},
		{"non JSON", "true", "false", ""},
		{"device selector", "true", "true", "boarda"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, value := range map[string]string{"facts-boards": "boarda,boardb", "facts": tc.facts, "json": tc.json, "device": tc.device} {
				flag := flags.Lookup(name)
				oldValue, oldChanged := flag.Value.String(), flag.Changed
				if name == "facts-boards" {
					oldValue = strings.Trim(oldValue, "[]")
				}
				t.Cleanup(func() {
					if err := flag.Value.Set(oldValue); err != nil {
						t.Fatal(err)
					}
					flag.Changed = oldChanged
				})
				if err := flags.Set(name, value); err != nil {
					t.Fatal(err)
				}
			}
			err := symbolsCmd.RunE(symbolsCmd, []string{"missing.ipsw"})
			if err == nil || !strings.Contains(err.Error(), "--facts-boards requires") {
				t.Fatalf("invalid flags reached source I/O: %v", err)
			}
		})
	}
}
