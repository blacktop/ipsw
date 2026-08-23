package download

import (
	"strings"
	"testing"

	"github.com/blacktop/ipsw/internal/download"
)

// resetConcurrencyState restores the engine policy and the shared
// DownloadCmd flag state after a test. Cleanup must NOT go through
// viper.Set: override-level values permanently outrank the flag binding
// for the rest of the process.
func resetConcurrencyState(t *testing.T) {
	t.Helper()
	prev := download.GetConcurrency()
	t.Cleanup(func() {
		if err := download.SetConcurrency(prev); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"parts", "min-parts"} {
			f := DownloadCmd.PersistentFlags().Lookup(name)
			if err := f.Value.Set(f.DefValue); err != nil {
				t.Fatal(err)
			}
			f.Changed = false
		}
	})
}

// TestDownloadConcurrencyFlagsReachEngine drives the root-level concurrency
// resolution the way every command invocation does.
func TestDownloadConcurrencyFlagsReachEngine(t *testing.T) {
	resetConcurrencyState(t)

	if err := DownloadCmd.PersistentFlags().Set("parts", "6"); err != nil {
		t.Fatal(err)
	}
	if err := DownloadCmd.PersistentFlags().Set("min-parts", "3"); err != nil {
		t.Fatal(err)
	}
	if err := ApplyConcurrency(); err != nil {
		t.Fatal(err)
	}
	if got := download.GetConcurrency(); got != (download.Concurrency{Parts: 6, MinParts: 3}) {
		t.Fatalf("engine policy = %+v, want parts 6 / min-parts 3", got)
	}

	if err := DownloadCmd.PersistentFlags().Set("min-parts", "7"); err != nil {
		t.Fatal(err)
	}
	err := ApplyConcurrency()
	if err == nil || !strings.Contains(err.Error(), "min-parts") {
		t.Fatalf("ApplyConcurrency accepted min-parts above parts: %v", err)
	}
}

// TestDownloadConcurrencyClampsUnsetMinParts pins the fix for `--parts 2`
// failing because the untouched min-parts default exceeded it.
func TestDownloadConcurrencyClampsUnsetMinParts(t *testing.T) {
	resetConcurrencyState(t)

	if err := DownloadCmd.PersistentFlags().Set("parts", "2"); err != nil {
		t.Fatal(err)
	}
	if err := ApplyConcurrency(); err != nil {
		t.Fatalf("ApplyConcurrency() with only --parts lowered: %v", err)
	}
	if got := download.GetConcurrency(); got != (download.Concurrency{Parts: 2, MinParts: 2}) {
		t.Fatalf("engine policy = %+v, want min-parts clamped to parts 2", got)
	}
}

func TestDownloadConcurrencyDefaults(t *testing.T) {
	if got := DownloadCmd.PersistentFlags().Lookup("parts").DefValue; got != "8" {
		t.Fatalf("--parts default = %s, want 8", got)
	}
	// ramping is opt-in: the default floor equals the cap
	if got := DownloadCmd.PersistentFlags().Lookup("min-parts").DefValue; got != "8" {
		t.Fatalf("--min-parts default = %s, want 8", got)
	}
}
