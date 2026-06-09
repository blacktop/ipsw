package macho

import "testing"

func TestGeneratedExclaveKeyFromSkippedBundle(t *testing.T) {
	skipped := map[string]struct{}{
		"Firmware/image4/exclavecore_bundle.t8150.RELEASE.im4p": {},
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "generated exclave app key",
			path: "Firmware/image4/exclavecore_bundle.t8150.RELEASE.im4p/exclave_sharedcache",
			want: true,
		},
		{
			name: "base bundle member",
			path: "Firmware/image4/exclavecore_bundle.t8150.RELEASE.im4p",
			want: false,
		},
		{
			name: "different bundle variant",
			path: "Firmware/image4/exclavecore_bundle.t8150.RELEASE.restore.im4p/exclave_sharedcache",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := generatedExclaveKeyFromSkippedBundle(tt.path, skipped); got != tt.want {
				t.Fatalf("generatedExclaveKeyFromSkippedBundle(%q) = %t, want %t", tt.path, got, tt.want)
			}
		})
	}
}
