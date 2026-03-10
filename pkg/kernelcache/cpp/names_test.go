package cpp

import "testing"

func TestRecoveredClassNameFromSymbol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		symbol string
		want   string
	}{
		{symbol: "__ZTV11IOMemoryMap", want: "IOMemoryMap"},
		{symbol: "__ZTVN12IOUserClient9MetaClassE", want: "IOUserClient"},
		{symbol: "__ZN11IOMemoryMapC2Ev", want: "IOMemoryMap"},
		{symbol: "_vm_map_init", want: ""},
	}

	for _, tt := range tests {
		if got := recoveredClassNameFromSymbol(tt.symbol); got != tt.want {
			t.Fatalf("recoveredClassNameFromSymbol(%q) = %q, want %q", tt.symbol, got, tt.want)
		}
	}
}

func TestLooksLikeRecoveredClassNameRejectsNonsense(t *testing.T) {
	t.Parallel()

	invalid := []string{
		"",
		"/arm-io/sgx",
		"%2hhx",
		"\"",
		"bad.name",
		"vm_map_init",
		"atm_init",
	}
	for _, name := range invalid {
		if looksLikeRecoveredClassName(name) {
			t.Fatalf("expected %q to be rejected as a class name", name)
		}
	}
}

func TestLooksLikeRecoveredClassNameAllowsKnownLowercaseIdentifiers(t *testing.T) {
	t.Parallel()

	valid := []string{
		"cache",
		"client_log_buffer_t",
		"com_apple_filesystems_apfs",
		"com_apple_filesystems_hfs",
		"com_apple_filesystems_lifs",
	}
	for _, name := range valid {
		if !looksLikeRecoveredClassName(name) {
			t.Fatalf("expected %q to be accepted as a class name", name)
		}
	}
}

func TestDedupePrefersResolvedNamedClass(t *testing.T) {
	t.Parallel()

	s := &Scanner{}
	in := []discoveredClass{
		{
			Class: Class{
				Name:      "AppleSmartBattery",
				Bundle:    "com.apple.driver.AppleSmartBatteryManagerEmbedded",
				MetaPtr:   0xfffffe000761db30,
				SuperMeta: 0xfffffe000b312ec0,
				Size:      0x250,
				Ctor:      0xfffffe0009bf7d48,
			},
		},
		{
			Class: Class{
				Name:           "AppleSmartBattery",
				Bundle:         "com.apple.driver.AppleSmartBatteryManagerEmbedded",
				MetaPtr:        0xfffffe000b4a7da0,
				SuperMeta:      0xfffffe000b312ec0,
				Size:           0x250,
				Ctor:           0xfffffe0009bf76f8,
				VtableAddr:     0xfffffe0007fb4ed0,
				MetaVtableAddr: 0xfffffe0007fb5430,
			},
		},
	}

	out := s.dedupe(in)
	if len(out) != 1 {
		t.Fatalf("dedupe returned %d classes, want 1", len(out))
	}
	if got := out[0].MetaPtr; got != 0xfffffe000b4a7da0 {
		t.Fatalf("dedupe kept meta %#x, want %#x", got, uint64(0xfffffe000b4a7da0))
	}
	if out[0].VtableAddr == 0 || out[0].MetaVtableAddr == 0 {
		t.Fatalf("dedupe dropped resolved vtable data: %+v", out[0].Class)
	}
}
