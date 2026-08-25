package download

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/viper"

	internaldownload "github.com/blacktop/ipsw/internal/download"
)

func TestDownloadHelpAdvertisesNodeSelection(t *testing.T) {
	var output bytes.Buffer
	DownloadCmd.SetOut(&output)
	t.Cleanup(func() { DownloadCmd.SetOut(nil) })
	if err := DownloadCmd.Help(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "--enable-node-selection") {
		t.Errorf("download help does not advertise --enable-node-selection:\n%s", output.String())
	}
}

func resetConcurrencyState(t *testing.T) {
	t.Helper()
	prev := internaldownload.GetPolicyOverrides()
	t.Cleanup(func() {
		if err := internaldownload.SetPolicyOverrides(prev); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{
			"parts", "min-parts", "min-part-size", "enable-node-selection",
		} {
			flag := DownloadCmd.PersistentFlags().Lookup(name)
			if err := flag.Value.Set(flag.DefValue); err != nil {
				t.Fatal(err)
			}
			flag.Changed = false
		}
	})
}

func TestDownloadPolicyFlagsReachEngine(t *testing.T) {
	resetConcurrencyState(t)

	for _, flag := range []struct{ name, value string }{
		{"parts", "6"}, {"min-parts", "3"}, {"min-part-size", "12"},
		{"enable-node-selection", "true"},
	} {
		if err := DownloadCmd.PersistentFlags().Set(flag.name, flag.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := ApplyDownloadPolicy(); err != nil {
		t.Fatal(err)
	}
	want := internaldownload.PolicyOverrides{
		Parts: 6, MinParts: 3, MinPartSize: 12 << 20, EnableNodeSelection: true,
	}
	if got := internaldownload.GetPolicyOverrides(); got != want {
		t.Fatalf("policy overrides = %+v, want %+v", got, want)
	}

	if err := DownloadCmd.PersistentFlags().Set("min-parts", "7"); err != nil {
		t.Fatal(err)
	}
	if err := ApplyDownloadPolicy(); err == nil || !strings.Contains(err.Error(), "min-parts") {
		t.Fatalf("ApplyDownloadPolicy accepted min-parts above parts: %v", err)
	}
}

func TestDownloadPolicyRejectsNegativeMinPartSize(t *testing.T) {
	resetConcurrencyState(t)

	// a large negative MiB value would wrap positive after <<20 without the
	// pre-shift bound; a small one must be reported in MiB, not bytes
	for _, value := range []string{"-1", "-8796093022209"} {
		if err := DownloadCmd.PersistentFlags().Set("min-part-size", value); err != nil {
			t.Fatal(err)
		}
		err := ApplyDownloadPolicy()
		if err == nil || !strings.Contains(err.Error(), "must be >= 0 MiB, got "+value) {
			t.Fatalf("ApplyDownloadPolicy(min-part-size=%s) = %v, want MiB rejection",
				value, err)
		}
	}
}

func TestDownloadPolicyClampsInheritedMinParts(t *testing.T) {
	resetConcurrencyState(t)

	if err := DownloadCmd.PersistentFlags().Set("parts", "2"); err != nil {
		t.Fatal(err)
	}
	if err := ApplyDownloadPolicy(); err != nil {
		t.Fatalf("ApplyDownloadPolicy() with only --parts lowered: %v", err)
	}
	for _, profile := range []internaldownload.Profile{
		internaldownload.GenericProfile, internaldownload.AppleCDNProfile,
	} {
		policy := internaldownload.ResolvePolicy("::", profile)
		if policy.Parts != 2 || policy.MinParts != 2 {
			t.Fatalf("profile %d policy = %+v, want parts/min-parts 2/2", profile, policy)
		}
	}
}

func TestDownloadPolicyFlagDefaultsUseProfiles(t *testing.T) {
	for _, name := range []string{"parts", "min-parts", "min-part-size"} {
		if got := DownloadCmd.PersistentFlags().Lookup(name).DefValue; got != "0" {
			t.Fatalf("--%s default = %s, want 0", name, got)
		}
	}
	if got := DownloadCmd.PersistentFlags().Lookup("enable-node-selection").DefValue; got != "false" {
		t.Fatalf("--enable-node-selection default = %s, want false", got)
	}
}

func TestConfigIntRejectsLossyValues(t *testing.T) {
	for _, value := range []any{true, 7.5, float32(2.25)} {
		viper.Set("download.parts", value)
		t.Cleanup(func() { viper.Set("download.parts", nil) })
		if _, err := configInt("download.parts"); err == nil {
			t.Errorf("configInt accepted lossy value %v (%T)", value, value)
		}
	}
	viper.Set("download.parts", 6.0) // whole-number float (JSON configs)
	if got, err := configInt("download.parts"); err != nil || got != 6 {
		t.Errorf("configInt(6.0) = (%d, %v), want (6, nil)", got, err)
	}
}
