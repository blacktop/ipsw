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
