package download

import (
	"slices"
	"testing"
)

func TestGetRequestAssetTypesDeltaSelection(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		delta    bool
		want     []assetType
	}{
		{
			name:     "watchOS full OTA",
			platform: "watchos",
			want:     []assetType{softwareUpdate},
		},
		{
			name:     "watchOS delta OTA",
			platform: "watchos",
			delta:    true,
			want:     []assetType{recoveryOSUpdate, softwareUpdate},
		},
		{
			name:     "visionOS keeps recovery assets",
			platform: "visionos",
			want:     []assetType{recoveryOSUpdate, softwareUpdate},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := Ota{Config: OtaConf{Platform: tt.platform, Delta: tt.delta}}
			got, err := o.getRequestAssetTypes()
			if err != nil {
				t.Fatalf("getRequestAssetTypes() failed: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("getRequestAssetTypes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAssetAudienceIDsIncludes27Betas(t *testing.T) {
	t.Parallel()

	const version = "27"

	audiences, err := GetAssetAudienceIDs()
	if err != nil {
		t.Fatalf("GetAssetAudienceIDs() failed: %v", err)
	}

	tests := []struct {
		platform        string
		developerBetaID string
		appleSeedBetaID string
		publicBetaID    string
	}{
		{
			platform:        "ios",
			developerBetaID: "a5f921db-50af-448c-8f7e-3f093ca2c954",
			appleSeedBetaID: "c0ef13a7-d2dd-4e85-81c2-6f2b485271c0",
			publicBetaID:    "f0d176bc-9177-466c-9b82-35ab5c2e20a6",
		},
		{
			platform:        "macos",
			developerBetaID: "621ba5ab-54b6-4a71-891a-425ac0ce4551",
			appleSeedBetaID: "72407f94-0bee-4e80-a7a3-c246572648dd",
			publicBetaID:    "8c08f86a-5899-4e65-8a06-fbaa7abe410b",
		},
		{
			platform:        "tvos",
			developerBetaID: "6ca2978e-e976-48b5-9b85-cba646d5dea8",
			appleSeedBetaID: "077f811f-5ff5-4162-8bed-2820ffc2538f",
		},
		{
			platform:        "watchos",
			developerBetaID: "973a069a-8d0c-4247-8239-9493f14ee56e",
			appleSeedBetaID: "19b667c1-6315-436c-ad40-5c27dcd73470",
			publicBetaID:    "befb9f8e-527d-496b-8414-65b84665d509",
		},
		{
			platform:        "audioos",
			appleSeedBetaID: "377d5d3a-03bc-41ae-b1d9-96694d79d5c3",
		},
		{
			platform:        "visionos",
			developerBetaID: "3796f01d-bf07-45c2-8df6-ad7300055ed9",
			appleSeedBetaID: "6520bc19-c1ca-4232-b468-24019d13f591",
		},
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

			if got := audienceVersion.AppleSeedBeta; got != tt.appleSeedBetaID {
				t.Fatalf("%s version %s appleseed (customer) beta audience ID = %q, want %q", tt.platform, version, got, tt.appleSeedBetaID)
			}

			if tt.publicBetaID != "" {
				if got := audienceVersion.PublicBeta; got != tt.publicBetaID {
					t.Fatalf("%s version %s public beta audience ID = %q, want %q", tt.platform, version, got, tt.publicBetaID)
				}
			}

			if got := audiences.LatestVersion(tt.platform); got != version {
				t.Fatalf("%s latest audience version = %q, want %q", tt.platform, got, version)
			}
		})
	}
}
