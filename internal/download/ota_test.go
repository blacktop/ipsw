package download

import "testing"

func TestAssetAudienceIDsIncludes27DeveloperBetas(t *testing.T) {
	t.Parallel()

	const version = "27"

	audiences, err := GetAssetAudienceIDs()
	if err != nil {
		t.Fatalf("GetAssetAudienceIDs() failed: %v", err)
	}

	tests := []struct {
		platform        string
		developerBetaID string
	}{
		{platform: "ios", developerBetaID: "a5f921db-50af-448c-8f7e-3f093ca2c954"},
		{platform: "macos", developerBetaID: "621ba5ab-54b6-4a71-891a-425ac0ce4551"},
		{platform: "tvos", developerBetaID: "6ca2978e-e976-48b5-9b85-cba646d5dea8"},
		{platform: "watchos", developerBetaID: "973a069a-8d0c-4247-8239-9493f14ee56e"},
		{platform: "visionos", developerBetaID: "3796f01d-bf07-45c2-8df6-ad7300055ed9"},
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			platform, ok := audiences[tt.platform]
			if !ok {
				t.Fatalf("missing %q audience IDs", tt.platform)
			}

			audienceVersion, ok := platform.Versions[version]
			if !ok {
				t.Fatalf("missing %q version %s audience IDs", tt.platform, version)
			}

			if got := audienceVersion.DeveloperBeta; got != tt.developerBetaID {
				t.Fatalf("%s version %s developer beta audience ID = %q, want %q", tt.platform, version, got, tt.developerBetaID)
			}

			if got := audiences.LatestVersion(tt.platform); got != version {
				t.Fatalf("%s latest audience version = %q, want %q", tt.platform, got, version)
			}
		})
	}
}
