package download

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/ota/types"
	semver "github.com/hashicorp/go-version"
)

// Audience IDs pinned by the embedded database (see TestAssetAudienceIDsIncludes27Betas).
const (
	testIOSReleaseAudience   = "01c1d682-6e8f-4908-b724-5501fe3f5e5c"
	testIOSAlternateAudience = "c724cb61-e974-42d3-a911-ffd4dce11eda"
	testIOS27DevBetaAudience = "a5f921db-50af-448c-8f7e-3f093ca2c954"
)

func testOTAAsset(build, path string, devices []string, models []string) types.Asset {
	return types.Asset{
		AssetType:             string(softwareUpdate),
		Build:                 build,
		OSVersion:             "9.9.26.6.1",
		ProductSystemName:     "iOS",
		DocumentationID:       "iOS2661Long",
		BaseURL:               "https://updates.example/",
		RelativePath:          path,
		SupportedDevices:      devices,
		SupportedDeviceModels: models,
	}
}

func TestOTARecordsMergeSightingsAcrossAudiences(t *testing.T) {
	o := &Ota{}
	first := testOTAAsset("23G83", "full.aea", []string{"iPhone16,2", "iPhone16,1"}, []string{"D84AP"})
	second := testOTAAsset("23G83", "full.aea", []string{"iPhone16,1"}, []string{"D83AP"})

	o.noteSighting(first, OTASighting{Source: OTASourcePallas, AudienceID: testIOSAlternateAudience, AssetSetID: "set-alt", PostingDate: "2026-08-06"})
	o.noteSighting(second, OTASighting{Source: OTASourcePallas, AudienceID: testIOSReleaseAudience, AssetSetID: "set-rel", PostingDate: "2026-08-24"})
	o.noteSighting(second, OTASighting{Source: OTASourcePallas, AudienceID: testIOSReleaseAudience, AssetSetID: "set-rel", PostingDate: "2026-08-24"})

	records, err := o.Records([]types.Asset{second})
	if err != nil {
		t.Fatalf("Records() failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	record := records[0]
	if len(record.Sightings) != 2 {
		t.Fatalf("got %d sightings, want 2 (duplicate must collapse): %+v", len(record.Sightings), record.Sightings)
	}
	if got := record.Sightings[0]; got.AudienceName != OTAAudienceRelease || got.PostingDate != "2026-08-24" || got.AssetSetID != "set-rel" {
		t.Fatalf("release audience must rank first, got %+v", got)
	}
	if got := record.Sightings[1]; got.AudienceName != OTAAudienceAlternate || got.PostingDate != "2026-08-06" {
		t.Fatalf("alternate audience must rank second, got %+v", got)
	}
	if !slices.Equal(record.Devices, []string{"iPhone16,1", "iPhone16,2"}) {
		t.Fatalf("devices = %v, want sorted union", record.Devices)
	}
	if !slices.Equal(record.Models, []string{"D83AP", "D84AP"}) {
		t.Fatalf("models = %v, want sorted union", record.Models)
	}
}

func TestOTARecordsCanonicalizeAssetFromRankedSightings(t *testing.T) {
	release := testOTAAsset("23G83", "full.aea", []string{"iPhone16,1"}, []string{"D83AP"})
	release.Hash = []byte{0x23}
	release.HashAlgorithm = "SHA-1"
	release.BridgeVersionInfo.IsSeed = "NO"
	releaseVariant := release
	releaseVariant.Hash = []byte{0x24}
	releaseVariant.IsEncrypted = true
	releaseVariant.ArchiveDecryptionKey = "other-fake-key"

	alternate := testOTAAsset("24A1", "full.aea", []string{"iPhone16,2"}, []string{"D84AP"})
	alternate.OSVersion = "9.9.27.0"
	alternate.DocumentationID = "iOS27Beta"
	alternate.ReleaseType = "Beta"
	alternate.Hash = []byte{0x24}
	alternate.HashAlgorithm = "SHA-256"
	alternate.IsEncrypted = true
	alternate.ArchiveDecryptionKey = "fake-key"

	buildRecords := func(retained types.Asset, observations []types.Asset) ([]OTARecord, *Ota) {
		t.Helper()
		o := &Ota{as: &AssetSets{PublicAssetSets: map[string][]AssetSet{
			"iOS": {
				{ProductVersion: "26.6.1", Build: "23G83"},
				{ProductVersion: "27.0", Build: "24A1"},
			},
		}}}
		for _, asset := range observations {
			audience := testIOSAlternateAudience
			if asset.Build == release.Build {
				audience = testIOSReleaseAudience
			}
			o.noteSighting(asset, OTASighting{Source: OTASourcePallas, AudienceID: audience})
		}
		records, err := o.Records([]types.Asset{retained})
		if err != nil {
			t.Fatalf("Records() failed: %v", err)
		}
		return records, o
	}

	forward, resolver := buildRecords(alternate, []types.Asset{alternate, releaseVariant, release})
	backward, _ := buildRecords(releaseVariant, []types.Asset{release, releaseVariant, alternate})
	if !reflect.DeepEqual(forward, backward) {
		t.Fatalf("records depend on response order:\nforward: %+v\nbackward: %+v", forward, backward)
	}
	if len(forward) != 1 {
		t.Fatalf("got %d records, want 1", len(forward))
	}
	record := forward[0]
	if record.Asset.Build != release.Build || !reflect.DeepEqual(record.Asset.Hash, release.Hash) || record.Asset.IsEncrypted {
		t.Fatalf("canonical asset = %+v, want release-audience asset", record.Asset)
	}
	if len(record.Sightings) != 2 || record.Sightings[0].Build != record.Asset.Build {
		t.Fatalf("canonical asset and representative sighting disagree: asset=%+v sightings=%+v", record.Asset, record.Sightings)
	}
	if len(record.AssetSets) != 1 || record.AssetSets[0].Build != record.Asset.Build {
		t.Fatalf("asset-set match used a non-canonical build: asset=%+v sets=%+v", record.Asset, record.AssetSets)
	}
	record.Asset.Hash[0] = 0xff
	*record.Sightings[0].IsSeed = true
	repeat, err := resolver.Records([]types.Asset{alternate})
	if err != nil {
		t.Fatalf("repeat Records() failed: %v", err)
	}
	if len(repeat) != 1 || len(repeat[0].Sightings) == 0 {
		t.Fatalf("repeat Records() = %+v, want one record with sightings", repeat)
	}
	if !reflect.DeepEqual(repeat[0].Asset.Hash, []byte{0x23}) {
		t.Fatalf("mutating a returned asset changed resolver evidence: hash=%x", repeat[0].Asset.Hash)
	}
	if repeat[0].Sightings[0].IsSeed == nil || *repeat[0].Sightings[0].IsSeed {
		t.Fatalf("mutating a returned seed marker changed resolver evidence: %v", repeat[0].Sightings[0].IsSeed)
	}
}

func TestOTARecordsCanonicalAssetHonorsRequestedFilters(t *testing.T) {
	release := testOTAAsset("23G83", "full.aea", nil, nil)
	requested := testOTAAsset("24A1", "full.aea", nil, nil)
	requested.OSVersion = "9.9.27.0"
	requested.DocumentationID = "iOS27Beta"
	requested.ReleaseType = "Beta"

	version27, err := semver.NewVersion("27.0")
	if err != nil {
		t.Fatalf("parse test version: %v", err)
	}
	tests := []struct {
		name   string
		config OtaConf
		first  types.Asset
		match  types.Asset
	}{
		{name: "target build", config: OtaConf{Build: "24A1"}, first: release, match: requested},
		{name: "version", config: OtaConf{Version: version27, Build: "0"}, first: release, match: requested},
		{
			name:   "delta prerequisite",
			config: OtaConf{Build: "23G81", Delta: true},
			first: func() types.Asset {
				asset := release
				asset.Build = "24A1"
				asset.PrerequisiteBuild = "23G80"
				return asset
			}(),
			match: func() types.Asset { asset := requested; asset.PrerequisiteBuild = "23G81"; return asset }(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			o := &Ota{Config: test.config}
			o.noteSighting(test.first, OTASighting{Source: OTASourcePallas, AudienceID: testIOSReleaseAudience})
			o.noteSighting(test.match, OTASighting{Source: OTASourcePallas, AudienceID: testIOSAlternateAudience})

			records, err := o.Records([]types.Asset{test.match})
			if err != nil {
				t.Fatalf("Records() failed: %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("got %d records, want 1", len(records))
			}
			got := records[0].Asset
			if got.OSVersion != test.match.OSVersion || got.Build != test.match.Build || got.PrerequisiteBuild != test.match.PrerequisiteBuild {
				t.Fatalf("canonical identity = %s/%s prerequisite %s, want %s/%s prerequisite %s",
					got.OSVersion, got.Build, got.PrerequisiteBuild,
					test.match.OSVersion, test.match.Build, test.match.PrerequisiteBuild)
			}
		})
	}
}

func TestOTARecordsLabelSeedAudiencesAndKeepSeedMarkers(t *testing.T) {
	o := &Ota{}
	seed := true
	asset := testOTAAsset("24A5424a", "beta.aea", []string{"iPhone16,1"}, []string{"D83AP"})
	asset.OSVersion = "9.9.27.0"
	asset.DocumentationID = "iOS27Beta7"
	asset.ReleaseType = "Beta"
	asset.RestoreVersionInfo.IsSeed = seed
	o.noteSighting(asset, OTASighting{Source: OTASourcePallas, AudienceID: testIOS27DevBetaAudience, AssetSetID: "set-dev", PostingDate: "2026-08-24"})
	o.noteSighting(asset, OTASighting{Source: OTASourcePallas, AudienceID: "not-in-database", AssetSetID: "set-x"})

	records, err := o.Records([]types.Asset{asset})
	if err != nil {
		t.Fatalf("Records() failed: %v", err)
	}
	sightings := records[0].Sightings
	if len(sightings) != 2 {
		t.Fatalf("got %d sightings, want 2", len(sightings))
	}
	dev := sightings[0]
	if dev.AudienceName != OTAAudienceDeveloperBeta || dev.AudienceVersion != "27" {
		t.Fatalf("developer beta label = %q/%q, want developer-beta/27", dev.AudienceName, dev.AudienceVersion)
	}
	if dev.ReleaseType != "Beta" || dev.DocumentationID != "iOS27Beta7" || dev.IsSeed == nil || !*dev.IsSeed {
		t.Fatalf("seed markers not captured: %+v", dev)
	}
	unknown := sightings[1]
	if unknown.AudienceName != "" || unknown.AudienceVersion != "" || unknown.AudienceID != "not-in-database" {
		t.Fatalf("unknown audience must stay unlabeled, got %+v", unknown)
	}
}

func TestOTARecordsRankPallasBeforeMesu(t *testing.T) {
	o := &Ota{}
	asset := testOTAAsset("23G83", "full.zip", []string{"iPhone16,1"}, nil)
	o.noteSighting(asset, OTASighting{Source: OTASourceMesu})
	o.noteSighting(asset, OTASighting{Source: OTASourcePallas, AudienceID: testIOSReleaseAudience})

	records, err := o.Records([]types.Asset{asset})
	if err != nil {
		t.Fatalf("Records() failed: %v", err)
	}
	if got := records[0].Sightings[0].Source; got != OTASourcePallas {
		t.Fatalf("first sighting source = %q, want pallas", got)
	}
	if got := records[0].Sightings[1].Source; got != OTASourceMesu {
		t.Fatalf("second sighting source = %q, want mesu", got)
	}
}

func TestOTARecordsWithoutEvidenceStillCarryAssetDevices(t *testing.T) {
	o := &Ota{}
	asset := testOTAAsset("23G83", "full.zip", []string{"iPhone16,2", "iPhone16,1", "iPhone16,1"}, []string{"D84AP", "D83AP"})
	records, err := o.Records([]types.Asset{asset})
	if err != nil {
		t.Fatalf("Records() failed: %v", err)
	}
	record := records[0]
	if len(record.Sightings) != 0 {
		t.Fatalf("expected no sightings, got %+v", record.Sightings)
	}
	if !slices.Equal(record.Devices, []string{"iPhone16,1", "iPhone16,2"}) || !slices.Equal(record.Models, []string{"D83AP", "D84AP"}) {
		t.Fatalf("devices/models = %v/%v, want sorted unique", record.Devices, record.Models)
	}
	if record.AssetSets != nil {
		t.Fatalf("nil asset sets must match nothing, got %+v", record.AssetSets)
	}
}

func TestAssetSetsMatchBuild(t *testing.T) {
	as := &AssetSets{
		PublicAssetSets: map[string][]AssetSet{
			"iOS": {{ProductVersion: "26.6.1", Build: "23G83", PostingDate: "2026-08-24", ExpirationDate: "2026-11-27"}},
		},
		AssetSets: map[string][]AssetSet{
			"macOS": {{ProductVersion: "26.6.2", Build: "25G83", PostingDate: "2026-08-24"}},
			"iOS": {
				{ProductVersion: "26.6.1", Build: "23G6083", PostingDate: "2026-08-17"},
				{ProductVersion: "26.6.1", Build: "23G83", PostingDate: "2026-08-24", ExpirationDate: "2026-11-27"},
			},
		},
		PublicBackgroundSecurityImprovements: map[string][]AssetSet{
			"iOS": {{ProductVersion: "26.3.1", ProductVersionExtra: "(a)", Build: "23D771330a", PrerequisiteBuild: "23D8133", PostingDate: "2026-03-17"}},
		},
	}

	got := as.MatchBuild("23g83")
	want := []OTAAssetSetMatch{
		{List: "PublicAssetSets", OS: "iOS", ProductVersion: "26.6.1", Build: "23G83", PostingDate: "2026-08-24", ExpirationDate: "2026-11-27"},
		{List: "AssetSets", OS: "iOS", ProductVersion: "26.6.1", Build: "23G83", PostingDate: "2026-08-24", ExpirationDate: "2026-11-27"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("MatchBuild(23g83) = %+v, want %+v", got, want)
	}

	rsr := as.MatchBuild("23D771330a")
	if len(rsr) != 1 || rsr[0].List != "PublicBackgroundSecurityImprovements" || rsr[0].ProductVersionExtra != "(a)" || rsr[0].PrerequisiteBuild != "23D8133" {
		t.Fatalf("RSR match = %+v", rsr)
	}

	if got := as.MatchBuild("nope"); got != nil {
		t.Fatalf("unknown build matched %+v", got)
	}
	if got := as.MatchBuild(""); got != nil {
		t.Fatalf("empty build matched %+v", got)
	}
	var nilSets *AssetSets
	if got := nilSets.MatchBuild("23G83"); got != nil {
		t.Fatalf("nil receiver matched %+v", got)
	}
}

func TestSortOTARecordsIsDeterministic(t *testing.T) {
	mk := func(os, version, build, prereq, path string) OTARecord {
		return OTARecord{Asset: types.Asset{
			ProductSystemName: os, OSVersion: version, Build: build, PrerequisiteBuild: prereq,
			BaseURL: "https://updates.example/", RelativePath: path,
		}}
	}
	records := []OTARecord{
		mk("macOS", "26.6.2", "25G83", "", "mac.zip"),
		mk("iOS", "9.9.26.6.10", "23G100", "", "patch-ten.aea"),
		mk("iOS", "9.9.26.6.2", "23G20", "", "patch-two.aea"),
		mk("iOS", "9.9.26.6.1", "23G83", "", "b.aea"),
		mk("iOS", "9.9.26.6.1", "23G83", "", "a.aea"),
		mk("iOS", "9.9.26.6.1", "23G83", "23G80", "delta.aea"),
		mk("iOS", "9.9.27.0", "24A5424a", "", "beta.aea"),
		mk("iOS", "9.9.26.6.1", "23G6083", "", "short.aea"),
	}
	SortOTARecords(records)
	var got []string
	for _, r := range records {
		got = append(got, r.Asset.RelativePath)
	}
	want := []string{"beta.aea", "patch-ten.aea", "patch-two.aea", "delta.aea", "a.aea", "b.aea", "short.aea", "mac.zip"}
	if !slices.Equal(got, want) {
		t.Fatalf("sorted order = %v, want %v", got, want)
	}
}

func TestOTADelivery(t *testing.T) {
	tests := []struct {
		name  string
		asset types.Asset
		want  string
	}{
		{"full", types.Asset{AssetType: string(softwareUpdate)}, OTADeliveryFull},
		{"delta", types.Asset{AssetType: string(softwareUpdate), PrerequisiteBuild: "23G80"}, OTADeliveryDelta},
		{"splat only", types.Asset{AssetType: string(softwareUpdate), SplatOnly: true, PrerequisiteBuild: "23G80"}, OTADeliveryRSR},
		{"ios rsr type", types.Asset{AssetType: string(rsrUpdate), PrerequisiteBuild: "23G80"}, OTADeliveryRSR},
		{"mac rsr type", types.Asset{AssetType: string(macRsrUpdate)}, OTADeliveryRSR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OTADelivery(tt.asset); got != tt.want {
				t.Fatalf("OTADelivery() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOTAIsSeed(t *testing.T) {
	seed, notSeed := true, false
	var restoreFalse types.Asset
	if err := json.Unmarshal([]byte(`{"RestoreVersionInfo":{"IsSeed":false}}`), &restoreFalse); err != nil {
		t.Fatalf("decode explicit false seed marker: %v", err)
	}
	tests := []struct {
		name  string
		asset types.Asset
		want  *bool
	}{
		{"unsupplied", types.Asset{}, nil},
		{"restore seed", func() types.Asset { a := types.Asset{}; a.RestoreVersionInfo.IsSeed = seed; return a }(), &seed},
		{"restore explicit false", restoreFalse, &notSeed},
		{"bridge NO", func() types.Asset { a := types.Asset{}; a.BridgeVersionInfo.IsSeed = "NO"; return a }(), &notSeed},
		{"bridge YES", func() types.Asset { a := types.Asset{}; a.BridgeVersionInfo.IsSeed = "YES"; return a }(), &seed},
		{"bridge garbage", func() types.Asset { a := types.Asset{}; a.BridgeVersionInfo.IsSeed = "maybe"; return a }(), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := OTAIsSeed(tt.asset)
			switch {
			case got == nil && tt.want == nil:
			case got == nil || tt.want == nil || *got != *tt.want:
				t.Fatalf("OTAIsSeed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOTAVersionStripsLegacyPrefixAndFallsBackToSimulator(t *testing.T) {
	if got := OTAVersion(types.Asset{OSVersion: "9.9.26.6.1"}); got != "26.6.1" {
		t.Fatalf("OTAVersion() = %q, want 26.6.1", got)
	}
	if got := OTAVersion(types.Asset{OSVersion: "26.6.2"}); got != "26.6.2" {
		t.Fatalf("OTAVersion() = %q, want 26.6.2", got)
	}
	if got := OTAVersion(types.Asset{SimulatorVersion: "26.0"}); got != "26.0" {
		t.Fatalf("OTAVersion() = %q, want simulator version", got)
	}
}

func pallasJWS(payload string) io.ReadCloser {
	body := "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
	return io.NopCloser(strings.NewReader(body))
}

func TestDecodePallasResponse(t *testing.T) {
	const payload = `{"AssetAudience":"` + testIOSReleaseAudience + `","AssetSetId":"set-rel","PostingDate":"2026-08-24","Assets":[{"Build":"23G83","__BaseURL":"https://updates.example/","__RelativePath":"full.aea","RestoreVersionInfo":{"IsSeed":true}}]}`

	res, ok := decodePallasResponse(&http.Response{StatusCode: http.StatusOK, Body: pallasJWS(payload)})
	if !ok {
		t.Fatal("decodePallasResponse() rejected a valid response")
	}
	if res.AssetAudience != testIOSReleaseAudience || res.AssetSetID != "set-rel" || res.PostingDate != "2026-08-24" {
		t.Fatalf("response metadata not decoded: %+v", *res)
	}
	if len(res.Assets) != 1 || res.Assets[0].Build != "23G83" {
		t.Fatalf("assets not decoded: %+v", res.Assets)
	}
	if !res.Assets[0].RestoreVersionInfo.IsSeed || !res.Assets[0].RestoreVersionInfo.IsSeedPresent() {
		t.Fatalf("IsSeed presence lost: %+v", res.Assets[0].RestoreVersionInfo)
	}

	if _, ok := decodePallasResponse(&http.Response{StatusCode: http.StatusNotFound, Body: pallasJWS(payload)}); ok {
		t.Fatal("non-200 response must be skipped")
	}
	if _, ok := decodePallasResponse(&http.Response{StatusCode: http.StatusBadGateway, Body: pallasJWS(payload)}); ok {
		t.Fatal("5xx response must be skipped")
	}
	if _, ok := decodePallasResponse(&http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("not-a-jws"))}); ok {
		t.Fatal("malformed response must be skipped")
	}
}
