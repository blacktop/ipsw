package download

import "testing"

func TestAssetSetsLatestVisionOSUsesLivePMVKey(t *testing.T) {
	sets := &AssetSets{PublicAssetSets: map[string][]AssetSet{
		"visionOS": {{
			ProductVersion:   "27.1",
			Build:            "24B123",
			SupportedDevices: []string{"RealityDevice14,1"},
		}},
	}}

	if got := sets.LatestVersion("visionos"); got != "27.1" {
		t.Fatalf("LatestVersion(visionos) = %q, want 27.1", got)
	}
	if got := sets.LatestBuild("visionos"); got != "24B123" {
		t.Fatalf("LatestBuild(visionos) = %q, want 24B123", got)
	}
}
