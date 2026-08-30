package download

import (
	"slices"
	"testing"

	"github.com/blacktop/ipsw/pkg/ota/types"
	version "github.com/hashicorp/go-version"
)

func TestQueryPublicXMLRecordsMESUEvidenceBeforeDedup(t *testing.T) {
	wantedVersion, err := version.NewVersion("26.6.1")
	if err != nil {
		t.Fatalf("parse test version: %v", err)
	}
	release := testOTAAsset("23G83", "shared.aea", nil, nil)
	beta := release
	beta.Build = "23G84"
	beta.DocumentationID = "iOS2661Beta"
	beta.ReleaseType = "Beta"

	o := &Ota{
		ota:    ota{Assets: []types.Asset{release, beta}},
		Config: OtaConf{Platform: "ios", Version: wantedVersion, Build: "0"},
	}
	assets := o.QueryPublicXML()
	if len(assets) != 1 {
		t.Fatalf("QueryPublicXML() returned %d assets, want one URL-deduplicated asset", len(assets))
	}
	records, err := o.Records(assets)
	if err != nil {
		t.Fatalf("Records() failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Records() returned %d records, want 1", len(records))
	}
	if len(records[0].Sightings) != 2 {
		t.Fatalf("record has %d sightings, want 2", len(records[0].Sightings))
	}
	if got := ClassifyOTAChannel(records[0]); got != OTAChannelUnknown {
		t.Fatalf("channel = %q, want unknown for conflicting MESU evidence", got)
	}
}

func TestSelectRequestedOTAsFiltersBeforeURLDedup(t *testing.T) {
	version27, err := version.NewVersion("27.0")
	if err != nil {
		t.Fatalf("parse test version: %v", err)
	}
	release := testOTAAsset("23G83", "shared.aea", []string{"iPhone16,1"}, []string{"D83AP"})
	requested := release
	requested.Build = "24A1"
	requested.OSVersion = "9.9.27.0"
	requested.PrerequisiteBuild = "23G81"

	for _, test := range []struct {
		name   string
		config OtaConf
		first  types.Asset
		match  types.Asset
	}{
		{name: "target build", config: OtaConf{Platform: "ios", Build: requested.Build}, first: release, match: requested},
		{name: "version", config: OtaConf{Platform: "ios", Version: version27, Build: "0"}, first: release, match: requested},
		{
			name:   "delta prerequisite",
			config: OtaConf{Platform: "ios", Build: requested.PrerequisiteBuild, Delta: true},
			first:  func() types.Asset { asset := release; asset.PrerequisiteBuild = "23G80"; return asset }(),
			match:  requested,
		},
		{
			name:   "simulator target build",
			config: OtaConf{Platform: "ios", Build: requested.Build, Simulator: true},
			first:  func() types.Asset { asset := release; asset.AssetType = string(iOsSimulatorUpdate); return asset }(),
			match:  func() types.Asset { asset := requested; asset.AssetType = string(iOsSimulatorUpdate); return asset }(),
		},
	} {
		for _, ordering := range []struct {
			name   string
			assets []types.Asset
		}{
			{name: "nonmatching first", assets: []types.Asset{test.first, test.match}},
			{name: "matching first", assets: []types.Asset{test.match, test.first}},
		} {
			t.Run(test.name+"/"+ordering.name, func(t *testing.T) {
				o := &Ota{Config: test.config}
				got := o.selectRequestedOTAs(ordering.assets)
				if len(got) != 1 || got[0].Build != test.match.Build ||
					got[0].OSVersion != test.match.OSVersion || got[0].PrerequisiteBuild != test.match.PrerequisiteBuild {
					t.Fatalf("selected assets = %+v, want matching observation %+v", got, test.match)
				}
			})
		}
	}
}

func TestSelectRequestedOTAsDeduplicatesEarlyReturnModes(t *testing.T) {
	first := testOTAAsset("24A1", "shared.aea", []string{"iPhone16,1"}, []string{"D83AP"})
	second := first
	second.SupportedDevices = []string{"iPhone16,1", "iPhone16,2"}
	second.SupportedDeviceModels = []string{"D83AP", "D84AP"}

	for _, test := range []struct {
		name      string
		config    OtaConf
		assetType assetType
	}{
		{name: "macOS", config: OtaConf{Platform: "macos", Build: "0"}, assetType: macSoftwareUpdate},
		{name: "simulator", config: OtaConf{Platform: "ios", Build: first.Build, Simulator: true}, assetType: iOsSimulatorUpdate},
	} {
		t.Run(test.name, func(t *testing.T) {
			assets := []types.Asset{first, second}
			for idx := range assets {
				assets[idx].AssetType = string(test.assetType)
			}
			o := &Ota{Config: test.config}
			got := o.selectRequestedOTAs(assets)
			if len(got) != 1 {
				t.Fatalf("selected %d assets, want one URL-deduplicated asset", len(got))
			}
			if !slices.Equal(got[0].SupportedDevices, []string{"iPhone16,1", "iPhone16,2"}) ||
				!slices.Equal(got[0].SupportedDeviceModels, []string{"D83AP", "D84AP"}) {
				t.Fatalf("merged coverage = %v/%v", got[0].SupportedDevices, got[0].SupportedDeviceModels)
			}
		})
	}
}

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
			publicBetaID:    "976a551-4987-4dc5-aadf-e89d885515f0",
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
