package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGoldenParity captures or compares `ipsw diff` output for a fixed input
// pair, one feature subset at a time, so a parity regression bisects to a single
// feature. It is the guardrail for the mount.Session refactor (see
// docs/.ai/plans/diff-mount-session.md): the gate is byte-identical rendered
// markdown (which format.go renders deterministically by sorting map keys) plus
// a canonical JSON structural dump of the diff.
//
// It is opt-in and skips unless the input paths are provided:
//
//	DIFF_GOLDEN_OLD   path to the old IPSW/OTA/dir   (required)
//	DIFF_GOLDEN_NEW   path to the new IPSW/OTA/dir   (required)
//	DIFF_GOLDEN_DIR   baseline directory            (required)
//	DIFF_GOLDEN_UPDATE=1   (re)write baselines instead of comparing
//	DIFF_GOLDEN_SUBSETS=features,ent   limit to a comma-separated subset list
//	DIFF_GOLDEN_PEMDB / DIFF_GOLDEN_SIGS / DIFF_GOLDEN_KEYDB   optional inputs
//
// Capture baselines on master, then run again (without UPDATE) after each phase
// to prove the converted feature is byte-identical.
func TestGoldenParity(t *testing.T) {
	oldInput := os.Getenv("DIFF_GOLDEN_OLD")
	newInput := os.Getenv("DIFF_GOLDEN_NEW")
	dir := os.Getenv("DIFF_GOLDEN_DIR")
	if oldInput == "" || newInput == "" || dir == "" {
		t.Skip("set DIFF_GOLDEN_OLD, DIFF_GOLDEN_NEW, and DIFF_GOLDEN_DIR to run golden parity")
	}
	update := os.Getenv("DIFF_GOLDEN_UPDATE") == "1"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create baseline dir: %v", err)
	}

	subsets := []goldenSubset{
		{name: "machos"}, // default: machos + DSC
		{name: "ent", apply: func(c *Config) { c.Entitlements = true }},
		{name: "features", apply: func(c *Config) { c.Features = true }},
		{name: "localizations", apply: func(c *Config) { c.Localizations = true }},
		{name: "files", apply: func(c *Config) { c.Files = true }},
		{name: "launchd", apply: func(c *Config) { c.LaunchD = true }},
	}
	if only := os.Getenv("DIFF_GOLDEN_SUBSETS"); only != "" {
		want := make(map[string]bool)
		for s := range strings.SplitSeq(only, ",") {
			want[strings.TrimSpace(s)] = true
		}
		filtered := subsets[:0]
		for _, s := range subsets {
			if want[s.name] {
				filtered = append(filtered, s)
			}
		}
		subsets = filtered
	}

	for _, s := range subsets {
		t.Run(s.name, func(t *testing.T) {
			cfg := &Config{
				Title:      "golden",
				IpswOld:    oldInput,
				IpswNew:    newInput,
				Signatures: os.Getenv("DIFF_GOLDEN_SIGS"),
				AEAKeyDB:   os.Getenv("DIFF_GOLDEN_KEYDB"),
				PemDB:      os.Getenv("DIFF_GOLDEN_PEMDB"),
			}
			if s.apply != nil {
				s.apply(cfg)
			}
			d := New(cfg)
			if err := d.Diff(); err != nil {
				t.Fatalf("Diff(): %v", err)
			}
			md := d.String()
			js := canonicalJSON(t, d)

			compareOrUpdate(t, filepath.Join(dir, s.name+".md"), md, update)
			compareOrUpdate(t, filepath.Join(dir, s.name+".json"), js, update)
		})
	}
}

type goldenSubset struct {
	name  string
	apply func(*Config)
}

// canonicalJSON marshals the diff with encoding/json, which sorts map keys, so
// the dump is stable for the diff's map-heavy content across identical runs.
func canonicalJSON(t *testing.T, d *Diff) string {
	t.Helper()
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatalf("marshal diff: %v", err)
	}
	return string(b)
}

func compareOrUpdate(t *testing.T, path, got string, update bool) {
	t.Helper()
	if update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write baseline %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read baseline %s (run once with DIFF_GOLDEN_UPDATE=1): %v", path, err)
	}
	if string(want) != got {
		actual := path + ".actual"
		_ = os.WriteFile(actual, []byte(got), 0o644)
		t.Errorf("output changed vs baseline %s (wrote actual to %s)", path, actual)
	}
}
