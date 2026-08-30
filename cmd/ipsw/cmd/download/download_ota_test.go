package download

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/ota/types"
	"github.com/spf13/viper"
)

const (
	otaTestReleaseAudienceID   = "01c1d682-6e8f-4908-b724-5501fe3f5e5c"
	otaTestAlternateAudienceID = "c724cb61-e974-42d3-a911-ffd4dce11eda"
	otaTestDevBetaAudienceID   = "a5f921db-50af-448c-8f7e-3f093ca2c954"
	otaTestAppleSeedAudienceID = "c0ef13a7-d2dd-4e85-81c2-6f2b485271c0"
	otaTestDecryptionKey       = "FAKEKEYfakekeyFAKEKEYfakekeyFAKEKEYfakekey="
)

func otaFixtureRecord() download.OTARecord {
	return download.OTARecord{
		Asset: types.Asset{
			AssetType:             "com.apple.MobileAsset.SoftwareUpdate",
			Build:                 "23G83",
			OSVersion:             "9.9.26.6.1",
			ProductSystemName:     "iOS",
			DocumentationID:       "iOS2661Long",
			TrainName:             "LuckG",
			BaseURL:               "https://updates.example/",
			RelativePath:          "full.aea",
			SupportedDevices:      []string{"iPhone16,1"},
			SupportedDeviceModels: []string{"D83AP"},
			DownloadSize:          8724152320,
			UnarchivedSize:        8732758016,
			Hash:                  bytes.Repeat([]byte{0xab}, 20),
			HashAlgorithm:         "SHA-1",
			Sha256Hash:            bytes.Repeat([]byte{0xcd}, 32),
			IsEncrypted:           true,
			AssetFormat:           "AppleEncryptedArchive",
			ArchiveDecryptionKey:  otaTestDecryptionKey,
		},
		Sightings: []download.OTASighting{{
			Source:          download.OTASourcePallas,
			AudienceID:      otaTestReleaseAudienceID,
			AudienceName:    download.OTAAudienceRelease,
			AssetSetID:      "set-release",
			PostingDate:     "2026-08-24",
			OSVersion:       "9.9.26.6.1",
			Build:           "23G83",
			DocumentationID: "iOS2661Long",
		}},
		AssetSets: []download.OTAAssetSetMatch{{
			List: "PublicAssetSets", OS: "iOS", ProductVersion: "26.6.1", Build: "23G83",
			PostingDate: "2026-08-24", ExpirationDate: "2026-11-27",
		}},
		Devices: []string{"iPhone16,1"},
		Models:  []string{"D83AP"},
	}
}

func otaEnvelopeJSON(t *testing.T, records ...download.OTARecord) (string, otaJSONEnvelope) {
	t.Helper()
	raw, err := json.Marshal(newOTAJSONEnvelope(records))
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	var decoded otaJSONEnvelope
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("envelope is not valid JSON: %v", err)
	}
	return string(raw), decoded
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func TestNewOTAJSONEnvelopeReleaseFull(t *testing.T) {
	got, _ := otaEnvelopeJSON(t, otaFixtureRecord())
	want := `{"schema_version":1,"otas":[{"os":"iOS","version":"26.6.1","version_extra":null,"build":"23G83",` +
		`"channel":{"kind":"release","release_type":null,"documentation_id":"iOS2661Long","train_name":"LuckG","is_seed":null,` +
		`"audiences":[{"id":"` + otaTestReleaseAudienceID + `","name":"release","version":null}]},` +
		`"posting_date":"2026-08-24","delivery":"full","prerequisite":null,` +
		`"supported_devices":["iPhone16,1"],"supported_models":["D83AP"],"url":"https://updates.example/full.aea",` +
		`"download_size":8724152320,"unarchived_size":8732758016,` +
		`"sha1":"` + strings.Repeat("ab", 20) + `","sha256":"` + strings.Repeat("cd", 32) + `",` +
		`"encryption":{"encrypted":true,"format":"AppleEncryptedArchive","decryption_key_available":true},` +
		`"provenance":{"asset_type":"com.apple.MobileAsset.SoftwareUpdate",` +
		`"sightings":[{"source":"pallas","audience_id":"` + otaTestReleaseAudienceID + `","asset_set_id":"set-release",` +
		`"posting_date":"2026-08-24","build":"23G83","documentation_id":"iOS2661Long","release_type":null,"is_seed":null}],` +
		`"asset_sets":[{"list":"PublicAssetSets","os":"iOS","product_version":"26.6.1","product_version_extra":null,` +
		`"build":"23G83","prerequisite_build":null,"posting_date":"2026-08-24","expiration_date":"2026-11-27"}]}}]}`
	if got != want {
		t.Fatalf("envelope JSON mismatch:\n got: %s\nwant: %s", got, want)
	}
	if strings.Contains(got, otaTestDecryptionKey) {
		t.Fatal("envelope leaked the decryption key")
	}
}

func TestNewOTAJSONEnvelopeUsesSharedReleaseChannelVocabulary(t *testing.T) {
	_, env := otaEnvelopeJSON(t, otaFixtureRecord())
	if got := env.OTAs[0].Channel.Kind; got != "release" {
		t.Fatalf("channel.kind = %q, want release", got)
	}
}

func TestNewOTAJSONEnvelopeBetaSeed(t *testing.T) {
	seed := true
	record := otaFixtureRecord()
	record.Asset.OSVersion = "9.9.27.0"
	record.Asset.Build = "24A5424a"
	record.Asset.DocumentationID = "iOS27Beta7"
	record.Asset.ReleaseType = "Beta"
	record.Asset.TrainName = "RaveSeed"
	record.Asset.RestoreVersionInfo.IsSeed = seed
	record.Sightings = []download.OTASighting{{
		Source: download.OTASourcePallas, AudienceID: otaTestDevBetaAudienceID,
		AudienceName: download.OTAAudienceDeveloperBeta, AudienceVersion: "27",
		AssetSetID: "set-dev", PostingDate: "2026-08-24",
		OSVersion: "9.9.27.0", Build: "24A5424a", DocumentationID: "iOS27Beta7", ReleaseType: "Beta", IsSeed: &seed,
	}}
	record.AssetSets = nil

	_, env := otaEnvelopeJSON(t, record)
	ota := env.OTAs[0]
	if ota.Channel.Kind != download.OTAChannelBeta {
		t.Fatalf("kind = %q, want beta", ota.Channel.Kind)
	}
	if deref(ota.Channel.ReleaseType) != "Beta" || deref(ota.Channel.DocumentationID) != "iOS27Beta7" || deref(ota.Channel.TrainName) != "RaveSeed" {
		t.Fatalf("channel evidence = %+v", ota.Channel)
	}
	if ota.Channel.IsSeed == nil || !*ota.Channel.IsSeed {
		t.Fatalf("is_seed = %v, want true", ota.Channel.IsSeed)
	}
	if len(ota.Channel.Audiences) != 1 || ota.Channel.Audiences[0].ID != otaTestDevBetaAudienceID ||
		deref(ota.Channel.Audiences[0].Name) != "developer-beta" || deref(ota.Channel.Audiences[0].Version) != "27" {
		t.Fatalf("audiences = %+v", ota.Channel.Audiences)
	}
	if deref(ota.Version) != "27.0" || deref(ota.Build) != "24A5424a" {
		t.Fatalf("version/build = %s/%s", deref(ota.Version), deref(ota.Build))
	}
	if len(ota.Provenance.AssetSets) != 0 {
		t.Fatalf("beta without pmv entry must have empty asset_sets, got %+v", ota.Provenance.AssetSets)
	}
	if len(ota.Provenance.Sightings) != 1 || ota.Provenance.Sightings[0].IsSeed == nil || !*ota.Provenance.Sightings[0].IsSeed {
		t.Fatalf("sighting must carry its own is_seed: %+v", ota.Provenance.Sightings)
	}
}

func TestNewOTAJSONEnvelopeConflictingChannelEvidenceIsUnknown(t *testing.T) {
	seed := true
	mixed := otaFixtureRecord()
	mixed.Sightings = append(mixed.Sightings, download.OTASighting{
		Source: download.OTASourcePallas, AudienceID: otaTestDevBetaAudienceID, AudienceName: download.OTAAudienceDeveloperBeta,
		AudienceVersion: "27", AssetSetID: "set-dev", PostingDate: "2026-08-24",
		Build: "23G6083", DocumentationID: "iOS2661Short", ReleaseType: "Beta", IsSeed: &seed,
	})

	rcVersusRelease := otaFixtureRecord()
	rcVersusRelease.Asset.RelativePath = "rc.aea"
	rcVersusRelease.Asset.DocumentationID = "iOS2661RC"

	assetOnlyBeta := otaFixtureRecord()
	assetOnlyBeta.Asset.RelativePath = "asset-beta.aea"
	assetOnlyBeta.Asset.ReleaseType = "Beta"

	_, env := otaEnvelopeJSON(t, mixed, rcVersusRelease, assetOnlyBeta)
	if len(env.OTAs) != 3 {
		t.Fatalf("got %d otas, want 3", len(env.OTAs))
	}
	for _, ota := range env.OTAs {
		if ota.Channel.Kind != download.OTAChannelUnknown {
			t.Fatalf("%s kind = %q, want unknown on conflicting evidence", ota.URL, ota.Channel.Kind)
		}
	}
	mixedOTA := env.OTAs[slices.IndexFunc(env.OTAs, func(o otaJSONAsset) bool { return o.URL == "https://updates.example/full.aea" })]
	if len(mixedOTA.Provenance.Sightings) != 2 {
		t.Fatalf("conflicting sightings must both survive: %+v", mixedOTA.Provenance.Sightings)
	}
	if got := mixedOTA.Provenance.Sightings[1]; got.IsSeed == nil || !*got.IsSeed || deref(got.ReleaseType) != "Beta" {
		t.Fatalf("beta sighting evidence must be preserved: %+v", got)
	}
	if mixedOTA.Provenance.Sightings[0].IsSeed != nil {
		t.Fatalf("release sighting must not gain a seed marker: %+v", mixedOTA.Provenance.Sightings[0])
	}
}

func TestNewOTAJSONEnvelopeAgreeingEvidenceStillClassifies(t *testing.T) {
	seed := true
	record := otaFixtureRecord()
	record.Asset.OSVersion = "9.9.27.0"
	record.Asset.Build = "24A5424a"
	record.Asset.DocumentationID = "iOS27Beta7"
	record.Asset.ReleaseType = "Beta"
	record.Asset.RestoreVersionInfo.IsSeed = seed
	record.AssetSets = nil
	record.Sightings = []download.OTASighting{
		{Source: download.OTASourcePallas, AudienceID: otaTestDevBetaAudienceID, AudienceName: download.OTAAudienceDeveloperBeta, AudienceVersion: "27", DocumentationID: "iOS27Beta7", ReleaseType: "Beta", IsSeed: &seed},
		{Source: download.OTASourcePallas, AudienceID: otaTestAppleSeedAudienceID, AudienceName: download.OTAAudienceAppleSeedBeta, AudienceVersion: "27", DocumentationID: "iOS27Beta7", ReleaseType: "Beta", IsSeed: &seed},
		{Source: download.OTASourcePallas, AudienceID: "f0d176bc-9177-466c-9b82-35ab5c2e20a6", AudienceName: download.OTAAudiencePublicBeta, AudienceVersion: "27", DocumentationID: "iOS27PublicBeta5", ReleaseType: "Beta", IsSeed: &seed},
	}
	_, env := otaEnvelopeJSON(t, record)
	if got := env.OTAs[0].Channel.Kind; got != download.OTAChannelBeta {
		t.Fatalf("kind = %q, want beta when every vote is beta", got)
	}
}

func TestNewOTAJSONEnvelopeUndecidedChannelEvidenceIsUnknown(t *testing.T) {
	seed := true
	release := otaFixtureRecord()
	release.Sightings = append(release.Sightings, download.OTASighting{
		Source: download.OTASourcePallas, AudienceID: otaTestAppleSeedAudienceID,
		AudienceName: download.OTAAudienceAppleSeedBeta, AudienceVersion: "27",
	})

	beta := otaFixtureRecord()
	beta.Asset.RelativePath = "beta-with-undecided.aea"
	beta.Asset.DocumentationID = "iOS27Beta7"
	beta.Asset.ReleaseType = "Beta"
	beta.Asset.RestoreVersionInfo.IsSeed = seed
	beta.Sightings = []download.OTASighting{
		{Source: download.OTASourcePallas, AudienceID: otaTestDevBetaAudienceID, AudienceName: download.OTAAudienceDeveloperBeta, AudienceVersion: "27", DocumentationID: "iOS27Beta7", ReleaseType: "Beta", IsSeed: &seed},
		{Source: download.OTASourcePallas, AudienceID: otaTestAppleSeedAudienceID, AudienceName: download.OTAAudienceAppleSeedBeta, AudienceVersion: "27", IsSeed: &seed},
	}

	_, env := otaEnvelopeJSON(t, release, beta)
	if len(env.OTAs) != 2 {
		t.Fatalf("got %d otas, want 2", len(env.OTAs))
	}
	for _, ota := range env.OTAs {
		if ota.Channel.Kind != download.OTAChannelUnknown {
			t.Fatalf("%s kind = %q, want unknown when seed-audience evidence is undecided", ota.URL, ota.Channel.Kind)
		}
	}
}

func TestOTARepresentativeSightingMatchesCanonicalAsset(t *testing.T) {
	seed := true
	record := otaFixtureRecord()
	record.Asset.OSVersion = "9.9.27.0"
	record.Asset.Build = "24A1"
	record.Asset.DocumentationID = "iOS27Beta"
	record.Asset.ReleaseType = "Beta"
	record.Asset.RestoreVersionInfo.IsSeed = true
	record.Sightings = append(record.Sightings, download.OTASighting{
		Source: download.OTASourcePallas, AudienceID: otaTestAlternateAudienceID,
		AudienceName: download.OTAAudienceAlternate, OSVersion: "9.9.27.0", Build: "24A1",
		DocumentationID: "iOS27Beta", ReleaseType: "Beta", IsSeed: &seed,
	})

	got := otaRepresentativeSighting(record)
	if got.Build != record.Asset.Build || got.OSVersion != record.Asset.OSVersion ||
		got.DocumentationID != record.Asset.DocumentationID || got.ReleaseType != record.Asset.ReleaseType {
		t.Fatalf("representative = %+v, want canonical asset's sighting", got)
	}
}

func TestNewOTAJSONEnvelopePostingDateNullWhenAssetSetDisagrees(t *testing.T) {
	record := otaFixtureRecord()
	record.Sightings = append(record.Sightings, download.OTASighting{
		Source: download.OTASourceMesu, PostingDate: "2026-08-01", Build: "23G83",
	})
	record.AssetSets = append(record.AssetSets, download.OTAAssetSetMatch{
		List: "AssetSets", OS: "iOS", ProductVersion: "26.6.1", Build: "23G83", PostingDate: "2026-08-17",
	})
	_, env := otaEnvelopeJSON(t, record)
	ota := env.OTAs[0]
	if got := deref(ota.PostingDate); got != "2026-08-24" {
		t.Fatalf("posting_date = %q, want Pallas/PublicAssetSets agreement", got)
	}
	if len(ota.Provenance.AssetSets) != 2 || deref(ota.Provenance.AssetSets[1].PostingDate) != "2026-08-17" {
		t.Fatalf("pmv dates must survive in provenance: %+v", ota.Provenance.AssetSets)
	}

	publicDisagreement := otaFixtureRecord()
	publicDisagreement.AssetSets[0].PostingDate = "2026-08-17"
	_, env = otaEnvelopeJSON(t, publicDisagreement)
	if env.OTAs[0].PostingDate != nil {
		t.Fatalf("posting_date = %q, want null when PublicAssetSets disagrees with Pallas", *env.OTAs[0].PostingDate)
	}

	onlyPMV := otaFixtureRecord()
	onlyPMV.Sightings[0].PostingDate = ""
	_, env = otaEnvelopeJSON(t, onlyPMV)
	if deref(env.OTAs[0].PostingDate) != "2026-08-24" {
		t.Fatalf("a lone pmv date must be emitted, got %s", deref(env.OTAs[0].PostingDate))
	}
}

func TestNewOTAJSONEnvelopeRCOnlyFromDocumentationID(t *testing.T) {
	release := otaFixtureRecord()
	release.Asset.ProductSystemName = "macOS"
	release.Asset.OSVersion = "13.7.8"
	release.Asset.Build = "22H730"
	release.Asset.DocumentationID = "macOS1378RC"
	release.Asset.RelativePath = "mac.zip"
	release.Sightings[0].DocumentationID = "macOS1378RC"

	seed := true
	seeded := otaFixtureRecord()
	seeded.Asset.DocumentationID = "iOS27RC2"
	seeded.Asset.ReleaseType = "Beta"
	seeded.Asset.RelativePath = "rc.aea"
	seeded.Sightings = []download.OTASighting{{
		Source: download.OTASourcePallas, AudienceID: otaTestDevBetaAudienceID, AudienceName: download.OTAAudienceDeveloperBeta,
		AudienceVersion: "27", DocumentationID: "iOS27RC2", ReleaseType: "Beta", IsSeed: &seed,
	}}

	_, env := otaEnvelopeJSON(t, release, seeded)
	for _, ota := range env.OTAs {
		if ota.Channel.Kind != download.OTAChannelRC {
			t.Fatalf("%s kind = %q, want rc (documentation_id %s)", ota.URL, ota.Channel.Kind, deref(ota.Channel.DocumentationID))
		}
	}
}

func TestNewOTAJSONEnvelopeUncertainSeedStaysUnknown(t *testing.T) {
	seed := true
	uncertain := otaFixtureRecord()
	uncertain.Asset.DocumentationID = ""
	uncertain.Asset.RestoreVersionInfo.IsSeed = seed
	uncertain.Sightings = []download.OTASighting{{
		Source: download.OTASourcePallas, AudienceID: otaTestAppleSeedAudienceID, AudienceName: download.OTAAudienceAppleSeedBeta,
		AudienceVersion: "27", IsSeed: &seed,
	}}

	unlabeled := otaFixtureRecord()
	unlabeled.Asset.RelativePath = "unlabeled.aea"
	unlabeled.Asset.DocumentationID = ""
	unlabeled.Sightings = []download.OTASighting{{Source: download.OTASourcePallas, AudienceID: "not-in-database"}}

	oddType := otaFixtureRecord()
	oddType.Asset.RelativePath = "odd.aea"
	oddType.Asset.DocumentationID = ""
	oddType.Sightings[0].DocumentationID = ""
	oddType.Sightings[0].ReleaseType = "Internal"

	_, env := otaEnvelopeJSON(t, uncertain, unlabeled, oddType)
	if len(env.OTAs) != 3 {
		t.Fatalf("got %d otas, want 3", len(env.OTAs))
	}
	for _, ota := range env.OTAs {
		if ota.Channel.Kind != download.OTAChannelUnknown {
			t.Fatalf("%s kind = %q, want unknown", ota.URL, ota.Channel.Kind)
		}
	}
	seededOTA := env.OTAs[slices.IndexFunc(env.OTAs, func(o otaJSONAsset) bool { return o.URL == "https://updates.example/full.aea" })]
	if seededOTA.Channel.IsSeed == nil || !*seededOTA.Channel.IsSeed || deref(seededOTA.Channel.DocumentationID) != "<nil>" {
		t.Fatalf("seed evidence must be preserved without inventing a label: %+v", seededOTA.Channel)
	}
	unlabeledOTA := env.OTAs[slices.IndexFunc(env.OTAs, func(o otaJSONAsset) bool { return o.URL == "https://updates.example/unlabeled.aea" })]
	if len(unlabeledOTA.Channel.Audiences) != 1 || unlabeledOTA.Channel.Audiences[0].Name != nil {
		t.Fatalf("unknown audience must keep its ID with a null name: %+v", unlabeledOTA.Channel.Audiences)
	}
}

func TestNewOTAJSONEnvelopeDeltaCarriesPrerequisite(t *testing.T) {
	record := otaFixtureRecord()
	record.Asset.PrerequisiteBuild = "23G80"
	record.Asset.PrerequisiteOSVersion = "9.9.26.6"

	_, env := otaEnvelopeJSON(t, record)
	ota := env.OTAs[0]
	if ota.Delivery != download.OTADeliveryDelta {
		t.Fatalf("delivery = %q, want delta", ota.Delivery)
	}
	if ota.Prerequisite == nil || ota.Prerequisite.Build != "23G80" || deref(ota.Prerequisite.Version) != "26.6" {
		t.Fatalf("prerequisite = %+v", ota.Prerequisite)
	}
}

func TestNewOTAJSONEnvelopeRSRCarriesExtraAndAssetSet(t *testing.T) {
	record := otaFixtureRecord()
	record.Asset.AssetType = "com.apple.MobileAsset.SplatSoftwareUpdate"
	record.Asset.SplatOnly = true
	record.Asset.OSVersion = "9.9.26.3.1"
	record.Asset.ProductVersionExtra = "(a)"
	record.Asset.Build = "23D771330a"
	record.Asset.PrerequisiteBuild = "23D8133"
	record.Asset.PrerequisiteOSVersion = "9.9.26.3.1"
	record.Sightings[0].Build = "23D771330a"
	record.AssetSets = []download.OTAAssetSetMatch{{
		List: "PublicBackgroundSecurityImprovements", OS: "iOS", ProductVersion: "26.3.1", ProductVersionExtra: "(a)",
		Build: "23D771330a", PrerequisiteBuild: "23D8133", PostingDate: "2026-03-17", ExpirationDate: "2026-11-27",
	}}

	_, env := otaEnvelopeJSON(t, record)
	ota := env.OTAs[0]
	if ota.Delivery != download.OTADeliveryRSR || deref(ota.VersionExtra) != "(a)" || deref(ota.Version) != "26.3.1" {
		t.Fatalf("rsr identity = delivery %q version %s extra %s", ota.Delivery, deref(ota.Version), deref(ota.VersionExtra))
	}
	if ota.Prerequisite == nil || ota.Prerequisite.Build != "23D8133" {
		t.Fatalf("rsr prerequisite = %+v", ota.Prerequisite)
	}
	if len(ota.Provenance.AssetSets) != 1 {
		t.Fatalf("asset_sets = %+v", ota.Provenance.AssetSets)
	}
	set := ota.Provenance.AssetSets[0]
	if set.List != "PublicBackgroundSecurityImprovements" || deref(set.ProductVersionExtra) != "(a)" || deref(set.PrerequisiteBuild) != "23D8133" || deref(set.PostingDate) != "2026-03-17" {
		t.Fatalf("asset_set = %+v", set)
	}
}

func TestNewOTAJSONEnvelopeNullsMissingOptionals(t *testing.T) {
	record := otaFixtureRecord()
	record.Asset.AssetType = ""
	record.Asset.TrainName = ""
	record.Asset.AssetFormat = ""
	record.Asset.IsEncrypted = false
	record.Asset.ArchiveDecryptionKey = ""
	record.Asset.DownloadSize = 0
	record.Asset.UnarchivedSize = 0
	record.Asset.HashAlgorithm = ""
	record.Asset.Sha256Hash = nil
	record.Sightings = []download.OTASighting{{Source: download.OTASourceMesu, Build: "23G83", DocumentationID: "iOS2661Long"}}
	record.AssetSets = nil

	got, env := otaEnvelopeJSON(t, record)
	ota := env.OTAs[0]
	for name, value := range map[string]*string{
		"sha1": ota.SHA1, "sha256": ota.SHA256, "posting_date": ota.PostingDate,
		"train_name": ota.Channel.TrainName, "format": ota.Encryption.Format, "asset_type": ota.Provenance.AssetType,
	} {
		if value != nil {
			t.Fatalf("%s = %q, want null", name, *value)
		}
	}
	if ota.DownloadSize != nil || ota.UnarchivedSize != nil {
		t.Fatalf("sizes must be null when unsupplied: %v %v", ota.DownloadSize, ota.UnarchivedSize)
	}
	if ota.Encryption.Encrypted || ota.Encryption.KeyAvailable {
		t.Fatalf("encryption = %+v, want plaintext", ota.Encryption)
	}
	if ota.Channel.Kind != download.OTAChannelRelease {
		t.Fatalf("mesu public feed kind = %q, want release", ota.Channel.Kind)
	}
	if len(ota.Channel.Audiences) != 0 || len(ota.Provenance.AssetSets) != 0 {
		t.Fatalf("mesu sighting must yield empty audiences/asset_sets, got %+v / %+v", ota.Channel.Audiences, ota.Provenance.AssetSets)
	}
	if strings.Contains(got, `"audiences":null`) || strings.Contains(got, `"asset_sets":null`) || strings.Contains(got, `"sightings":null`) {
		t.Fatalf("lists must be [] not null: %s", got)
	}
}

func TestNewOTAJSONEnvelopePostingDateNullWhenSightingsDisagree(t *testing.T) {
	record := otaFixtureRecord()
	record.Sightings = append(record.Sightings, download.OTASighting{
		Source: download.OTASourcePallas, AudienceID: otaTestAlternateAudienceID, AudienceName: download.OTAAudienceAlternate,
		AssetSetID: "set-alt", PostingDate: "2026-08-06", Build: "23G83", DocumentationID: "iOS2661Long",
	})
	_, env := otaEnvelopeJSON(t, record)
	ota := env.OTAs[0]
	if ota.PostingDate != nil {
		t.Fatalf("posting_date = %q, want null on disagreement", *ota.PostingDate)
	}
	if len(ota.Provenance.Sightings) != 2 || deref(ota.Provenance.Sightings[1].PostingDate) != "2026-08-06" {
		t.Fatalf("both posting dates must survive in provenance: %+v", ota.Provenance.Sightings)
	}
	if len(ota.Channel.Audiences) != 2 || deref(ota.Channel.Audiences[1].Name) != "alternate" {
		t.Fatalf("audiences = %+v", ota.Channel.Audiences)
	}
}

func TestNewOTAJSONEnvelopeUsesSHA256MeasurementFallback(t *testing.T) {
	record := otaFixtureRecord()
	record.Asset.Hash = bytes.Repeat([]byte{0xee}, 32)
	record.Asset.HashAlgorithm = "SHA-256"
	record.Asset.Sha256Hash = nil

	_, env := otaEnvelopeJSON(t, record)
	ota := env.OTAs[0]
	if ota.SHA1 != nil {
		t.Fatalf("sha1 = %q, want null for a SHA-256 measurement", *ota.SHA1)
	}
	if got := deref(ota.SHA256); got != strings.Repeat("ee", 32) {
		t.Fatalf("sha256 = %q, want _Measurement fallback", got)
	}
}

func TestWriteOTAJSONEmitsExactEmptyEnvelope(t *testing.T) {
	var output bytes.Buffer
	if err := writeOTAJSON(&output, nil); err != nil {
		t.Fatalf("write empty envelope: %v", err)
	}
	const want = "{\n  \"schema_version\": 1,\n  \"otas\": []\n}\n"
	if output.String() != want {
		t.Fatalf("empty JSON output = %q, want %q", output.String(), want)
	}
	var decoded otaJSONEnvelope
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("empty JSON output is not valid JSON: %v", err)
	}
}

func TestNewOTAJSONEnvelopeDedupesAndSortsDeterministically(t *testing.T) {
	newest := otaFixtureRecord()
	newest.Asset.OSVersion = "9.9.27.0"
	newest.Asset.Build = "24A5424a"
	newest.Asset.RelativePath = "beta.aea"

	duplicate := otaFixtureRecord()
	duplicate.Asset.SupportedDevices = []string{"iPhone16,2"}
	duplicate.Devices = []string{"iPhone16,2"}
	duplicate.Asset.SupportedDeviceModels = []string{"D84AP"}
	duplicate.Models = nil

	mac := otaFixtureRecord()
	mac.Asset.ProductSystemName = "macOS"
	mac.Asset.OSVersion = "26.6.2"
	mac.Asset.RelativePath = "mac.zip"

	urlless := otaFixtureRecord()
	urlless.Asset.BaseURL = ""
	urlless.Asset.RelativePath = ""

	forward, envForward := otaEnvelopeJSON(t, newest, otaFixtureRecord(), duplicate, mac, urlless)
	backward, _ := otaEnvelopeJSON(t, urlless, mac, duplicate, otaFixtureRecord(), newest)
	if forward != backward {
		t.Fatalf("envelope depends on input order:\n%s\n%s", forward, backward)
	}
	var urls []string
	for _, ota := range envForward.OTAs {
		urls = append(urls, ota.URL)
	}
	want := []string{"https://updates.example/beta.aea", "https://updates.example/full.aea", "https://updates.example/mac.zip"}
	if !slices.Equal(urls, want) {
		t.Fatalf("urls = %v, want %v", urls, want)
	}
	merged := envForward.OTAs[1]
	if !slices.Equal(merged.SupportedDevices, []string{"iPhone16,1", "iPhone16,2"}) || !slices.Equal(merged.SupportedModels, []string{"D83AP", "D84AP"}) {
		t.Fatalf("duplicate URL must merge devices/models: %v %v", merged.SupportedDevices, merged.SupportedModels)
	}
}

func TestDownloadOTAJSONRejectsAlternateOutputModes(t *testing.T) {
	outputFlags := []string{"info", "show-latest-version", "show-latest-build", "fcs-keys", "urls", "json"}
	resetFlags := func() {
		for _, name := range outputFlags {
			flag := downloadOtaCmd.Flags().Lookup(name)
			if flag == nil {
				t.Fatalf("missing --%s flag", name)
			}
			if err := flag.Value.Set(flag.DefValue); err != nil {
				t.Fatalf("reset --%s: %v", name, err)
			}
			flag.Changed = false
		}
	}
	t.Cleanup(resetFlags)

	for left := range outputFlags {
		for right := left + 1; right < len(outputFlags); right++ {
			name := outputFlags[left] + "-" + outputFlags[right]
			t.Run(name, func(t *testing.T) {
				resetFlags()
				if err := downloadOtaCmd.Flags().Set(outputFlags[left], "true"); err != nil {
					t.Fatalf("set --%s: %v", outputFlags[left], err)
				}
				if err := downloadOtaCmd.Flags().Set(outputFlags[right], "true"); err != nil {
					t.Fatalf("set --%s: %v", outputFlags[right], err)
				}
				if err := downloadOtaCmd.ValidateFlagGroups(); err == nil {
					t.Fatalf("--%s with --%s passed flag validation", outputFlags[left], outputFlags[right])
				}
			})
		}
	}
}

func TestOTAOutputModesRejectResolvedConflicts(t *testing.T) {
	if err := (otaOutputModes{urls: true, json: true}).validate(); err == nil {
		t.Fatal("resolved --urls/--json conflict passed runtime validation")
	}
	if err := (otaOutputModes{json: true}).validate(); err != nil {
		t.Fatalf("single resolved output mode failed validation: %v", err)
	}
}

func TestDownloadOTARejectsResolvedBetaAndRC(t *testing.T) {
	for _, key := range []string{"download.ota.beta", "download.ota.rc"} {
		viper.Set(key, true)
		t.Cleanup(func() { viper.Set(key, nil) })
	}

	err := downloadOtaCmd.RunE(downloadOtaCmd, nil)
	if err == nil || err.Error() != "cannot combine --beta and --rc" {
		t.Fatalf("resolved beta/RC conflict returned %v", err)
	}
}

func TestSelectOTARecordsByChannelFailsClosed(t *testing.T) {
	release := otaFixtureRecord()

	beta := otaFixtureRecord()
	beta.Asset.RelativePath = "beta.aea"
	beta.Asset.DocumentationID = "iOS27Beta"
	beta.Asset.ReleaseType = "Beta"
	beta.Sightings[0].DocumentationID = "iOS27Beta"
	beta.Sightings[0].ReleaseType = "Beta"

	rc := otaFixtureRecord()
	rc.Asset.RelativePath = "rc.aea"
	rc.Asset.DocumentationID = "iOS27RC"
	rc.Asset.SupportedDevices = []string{"iPhone16,1"}
	rc.Asset.SupportedDeviceModels = []string{"D83AP"}
	rc.Sightings[0].DocumentationID = "iOS27RC"
	rc.Devices = []string{"iPhone16,1", "iPhone16,2"}
	rc.Models = []string{"D83AP", "D84AP"}

	unknown := otaFixtureRecord()
	unknown.Asset.RelativePath = "unknown.aea"
	unknown.Asset.DocumentationID = ""
	unknown.Sightings[0].DocumentationID = ""
	unknown.Sightings[0].AudienceName = ""

	records, assets := selectOTARecordsByChannel(
		[]download.OTARecord{release, beta, unknown, rc}, download.OTAChannelRC,
	)
	if len(records) != 1 || len(assets) != 1 {
		t.Fatalf("RC selection returned %d records/%d assets, want 1/1", len(records), len(assets))
	}
	if got := download.OTAURL(records[0].Asset); got != "https://updates.example/rc.aea" {
		t.Fatalf("selected record URL = %q, want RC", got)
	}
	if got := download.OTAURL(assets[0]); got != "https://updates.example/rc.aea" {
		t.Fatalf("selected asset URL = %q, want RC", got)
	}
	if !slices.Equal(assets[0].SupportedDevices, rc.Devices) ||
		!slices.Equal(assets[0].SupportedDeviceModels, rc.Models) {
		t.Fatalf("selected asset coverage = %v/%v, want merged %v/%v",
			assets[0].SupportedDevices, assets[0].SupportedDeviceModels, rc.Devices, rc.Models)
	}
	assets[0].SupportedDevices[0] = "mutated"
	assets[0].SupportedDeviceModels[0] = "mutated"
	if records[0].Devices[0] == "mutated" || records[0].Models[0] == "mutated" {
		t.Fatal("selected asset shares its coverage slices with the record")
	}
}
