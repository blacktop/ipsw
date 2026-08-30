package download

import (
	"bytes"
	"cmp"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/ota/types"
	semver "github.com/hashicorp/go-version"
)

// OTA resolver sources.
const (
	OTASourcePallas = "pallas"
	OTASourceMesu   = "mesu"
)

// OTA delivery kinds.
const (
	OTADeliveryFull  = "full"
	OTADeliveryDelta = "delta"
	OTADeliveryRSR   = "rsr"
)

// Audience names from the embedded Pallas audience database.
const (
	OTAAudienceRelease       = "release"
	OTAAudienceAlternate     = "alternate"
	OTAAudienceGeneric       = "generic"
	OTAAudienceDeveloperBeta = "developer-beta"
	OTAAudienceAppleSeedBeta = "appleseed-beta"
	OTAAudiencePublicBeta    = "public-beta"
)

// OTA channel kinds shared by record selection and JSON presentation.
const (
	OTAChannelRelease = "release"
	OTAChannelBeta    = "beta"
	OTAChannelRC      = "rc"
	OTAChannelUnknown = "unknown"
	otaChannelAbstain = ""
)

var otaRCDocumentationID = regexp.MustCompile(`RC[0-9]*$`)

// OTASighting is one Apple response that advertised an OTA URL. Pallas serves
// the same URL to several audiences, sometimes under different build labels
// and documentation IDs, so a record keeps every sighting instead of silently
// picking one.
type OTASighting struct {
	Source          string
	AudienceID      string
	AudienceName    string // "" when the audience ID is not in the embedded database
	AudienceVersion string // major OS version for seed audiences, "" otherwise
	AssetSetID      string
	PostingDate     string
	OSVersion       string
	Build           string
	DocumentationID string
	ReleaseType     string
	IsSeed          *bool
}

// OTAAssetSetMatch is a gdmf pmv entry whose build matches an OTA.
type OTAAssetSetMatch struct {
	List                string
	OS                  string
	ProductVersion      string
	ProductVersionExtra string
	Build               string
	PrerequisiteBuild   string
	PostingDate         string
	ExpirationDate      string
}

// OTARecord pairs a resolved OTA with the evidence gathered while resolving
// it. Sightings are sorted; Asset is the deterministic observation compatible
// with the active query. Devices and Models are the sorted union across sightings.
type OTARecord struct {
	Asset     types.Asset
	Sightings []OTASighting
	AssetSets []OTAAssetSetMatch
	Devices   []string
	Models    []string
}

type otaEvidence struct {
	observations []otaObservation
	devices      []string
	models       []string
}

type otaObservation struct {
	asset    types.Asset
	sighting OTASighting
}

// pmv list names as Apple spells them in the asset-set feed.
const (
	OTAAssetSetListPublic     = "PublicAssetSets"
	otaAssetSetListInternal   = "AssetSets"
	otaAssetSetListBackground = "PublicBackgroundSecurityImprovements"
)

var otaAssetSetLists = []string{OTAAssetSetListPublic, otaAssetSetListInternal, otaAssetSetListBackground}

var otaAudienceRank = map[string]int{
	OTAAudienceRelease:       0,
	OTAAudienceAlternate:     1,
	OTAAudienceGeneric:       2,
	OTAAudienceDeveloperBeta: 3,
	OTAAudienceAppleSeedBeta: 4,
	OTAAudiencePublicBeta:    5,
}

// OTAURL is the exact download URL Apple advertised for an asset.
func OTAURL(asset types.Asset) string {
	return asset.BaseURL + asset.RelativePath
}

// OTAVersion is the bare product version (or simulator runtime version) with
// Apple's legacy "9.9." prefix removed and without the RSR suffix.
func OTAVersion(asset types.Asset) string {
	if asset.OSVersion == "" {
		return asset.SimulatorVersion
	}
	return strings.TrimPrefix(asset.OSVersion, "9.9.")
}

// OTADelivery classifies an asset as a full, delta, or RSR update.
func OTADelivery(asset types.Asset) string {
	switch {
	case asset.SplatOnly, assetType(asset.AssetType) == rsrUpdate, assetType(asset.AssetType) == macRsrUpdate:
		return OTADeliveryRSR
	case asset.PrerequisiteBuild != "":
		return OTADeliveryDelta
	}
	return OTADeliveryFull
}

// OTAIsSeed reports Apple's seed marker when it supplied one and nil when it
// did not. RestoreVersionInfo wins; BridgeVersionInfo spells it "YES"/"NO".
func OTAIsSeed(asset types.Asset) *bool {
	if asset.RestoreVersionInfo.IsSeed || asset.RestoreVersionInfo.IsSeedPresent() {
		seed := asset.RestoreVersionInfo.IsSeed
		return &seed
	}
	switch strings.ToUpper(asset.BridgeVersionInfo.IsSeed) {
	case "YES":
		seed := true
		return &seed
	case "NO":
		seed := false
		return &seed
	}
	return nil
}

func (o *Ota) noteSighting(asset types.Asset, sighting OTASighting) {
	url := OTAURL(asset)
	if url == "" {
		return
	}
	if o.evidence == nil {
		o.evidence = make(map[string]*otaEvidence)
	}
	ev := o.evidence[url]
	if ev == nil {
		ev = &otaEvidence{}
		o.evidence[url] = ev
	}
	sighting.OSVersion = asset.OSVersion
	sighting.Build = asset.Build
	sighting.DocumentationID = asset.DocumentationID
	sighting.ReleaseType = asset.ReleaseType
	sighting.IsSeed = cloneOptionalBool(OTAIsSeed(asset))
	observation := otaObservation{asset: cloneOTAAsset(asset), sighting: sighting}
	if !slices.ContainsFunc(ev.observations, func(existing otaObservation) bool {
		return compareOTAObservations(existing, observation) == 0
	}) {
		ev.observations = append(ev.observations, observation)
	}
	ev.devices = utils.Unique(append(ev.devices, asset.SupportedDevices...))
	ev.models = utils.Unique(append(ev.models, asset.SupportedDeviceModels...))
}

// Records attaches resolver evidence to the assets GetPallasOTAs returned.
// The result is sorted deterministically and shares no slices with the
// resolver state.
func (o *Ota) Records(assets []types.Asset) ([]OTARecord, error) {
	audiences, err := GetAssetAudienceIDs()
	if err != nil {
		return nil, err
	}
	labels := otaAudienceLabels(audiences)

	records := make([]OTARecord, 0, len(assets))
	for _, asset := range assets {
		record := OTARecord{
			Asset:   cloneOTAAsset(asset),
			Devices: slices.Clone(asset.SupportedDevices),
			Models:  slices.Clone(asset.SupportedDeviceModels),
		}
		if ev := o.evidence[OTAURL(asset)]; ev != nil {
			observations := slices.Clone(ev.observations)
			for idx := range observations {
				label := labels[observations[idx].sighting.AudienceID]
				observations[idx].sighting.AudienceName = label.name
				observations[idx].sighting.AudienceVersion = label.version
			}
			slices.SortFunc(observations, compareOTAObservations)
			for _, observation := range observations {
				sighting := observation.sighting
				sighting.IsSeed = cloneOptionalBool(sighting.IsSeed)
				record.Sightings = append(record.Sightings, sighting)
			}
			for _, observation := range observations {
				if o.matchesOTARecordFilters(observation.asset) {
					record.Asset = cloneOTAAsset(observation.asset)
					break
				}
			}
			record.Devices = append(record.Devices, ev.devices...)
			record.Models = append(record.Models, ev.models...)
		}
		record.Sightings = slices.CompactFunc(record.Sightings, func(a, b OTASighting) bool {
			return compareOTASightings(a, b) == 0
		})
		record.Devices = sortedUniqueStrings(record.Devices)
		record.Models = sortedUniqueStrings(record.Models)
		record.AssetSets = o.as.MatchBuild(record.Asset.Build)
		records = append(records, record)
	}
	SortOTARecords(records)
	return records, nil
}

// SortOTARecords orders records by OS, newest version first, newest build
// first, delivery, prerequisite build, and finally URL.
func SortOTARecords(records []OTARecord) {
	slices.SortFunc(records, compareOTARecords)
}

func compareOTARecords(a, b OTARecord) int {
	aVersion, bVersion := OTAVersion(a.Asset), OTAVersion(b.Asset)
	return cmp.Or(
		strings.Compare(a.Asset.ProductSystemName, b.Asset.ProductSystemName),
		-compareOTAVersions(aVersion, bVersion),
		-strings.Compare(aVersion, bVersion),
		-strings.Compare(a.Asset.Build, b.Asset.Build),
		strings.Compare(OTADelivery(a.Asset), OTADelivery(b.Asset)),
		strings.Compare(a.Asset.PrerequisiteBuild, b.Asset.PrerequisiteBuild),
		strings.Compare(OTAURL(a.Asset), OTAURL(b.Asset)),
	)
}

func compareOTAVersions(a, b string) int {
	aVersion, aErr := semver.NewVersion(a)
	bVersion, bErr := semver.NewVersion(b)
	switch {
	case aErr == nil && bErr == nil:
		return aVersion.Compare(bVersion)
	case aErr == nil:
		return 1
	case bErr == nil:
		return -1
	default:
		return 0
	}
}

func compareOTASightings(a, b OTASighting) int {
	return cmp.Or(
		cmp.Compare(otaSourceRank(a.Source), otaSourceRank(b.Source)),
		strings.Compare(a.Source, b.Source),
		cmp.Compare(otaAudienceRankOf(a.AudienceName), otaAudienceRankOf(b.AudienceName)),
		strings.Compare(a.AudienceName, b.AudienceName),
		strings.Compare(a.AudienceVersion, b.AudienceVersion),
		strings.Compare(a.AudienceID, b.AudienceID),
		strings.Compare(a.AssetSetID, b.AssetSetID),
		strings.Compare(a.PostingDate, b.PostingDate),
		strings.Compare(a.OSVersion, b.OSVersion),
		strings.Compare(a.Build, b.Build),
		strings.Compare(a.DocumentationID, b.DocumentationID),
		strings.Compare(a.ReleaseType, b.ReleaseType),
		compareOptionalBool(a.IsSeed, b.IsSeed),
	)
}

func compareOTAObservations(a, b otaObservation) int {
	return cmp.Or(
		compareOTASightings(a.sighting, b.sighting),
		compareOTAAssets(a.asset, b.asset),
	)
}

func cloneOTAAsset(asset types.Asset) types.Asset {
	asset.PreflightBuildManifest = slices.Clone(asset.PreflightBuildManifest)
	asset.PreflightGlobalSignatures = slices.Clone(asset.PreflightGlobalSignatures)
	asset.RSEPDigest = slices.Clone(asset.RSEPDigest)
	asset.SEPDigest = slices.Clone(asset.SEPDigest)
	asset.SupportedDeviceModels = slices.Clone(asset.SupportedDeviceModels)
	asset.SupportedDevices = slices.Clone(asset.SupportedDevices)
	asset.SystemPartitionPadding = maps.Clone(asset.SystemPartitionPadding)
	asset.Hash = slices.Clone(asset.Hash)
	asset.Sha256Hash = slices.Clone(asset.Sha256Hash)
	asset.Devices = slices.Clone(asset.Devices)
	asset.CryptexSizeInfo = slices.Clone(asset.CryptexSizeInfo)
	return asset
}

func (o *Ota) matchesOTARecordFilters(asset types.Asset) bool {
	if o.Config.Version != nil && o.Config.Version.Original() != "0" {
		if !o.matchesRequestedOTAVersion(asset) {
			return false
		}
	}
	if o.Config.Build != "" && o.Config.Build != "0" && !o.Config.RSR {
		if !o.matchesRequestedOTABuild(asset) {
			return false
		}
	}
	return true
}

func (o *Ota) matchesRequestedOTAVersion(asset types.Asset) bool {
	version, err := semver.NewVersion(OTAVersion(asset))
	return err == nil && o.Config.Version.Equal(version)
}

func (o *Ota) matchesRequestedOTABuild(asset types.Asset) bool {
	build := asset.Build
	if o.Config.Delta {
		build = asset.PrerequisiteBuild
	}
	return strings.EqualFold(build, o.Config.Build)
}

func cloneOptionalBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func compareOTAAssets(a, b types.Asset) int {
	return cmp.Or(
		strings.Compare(a.ProductSystemName, b.ProductSystemName),
		strings.Compare(a.OSVersion, b.OSVersion),
		strings.Compare(a.SimulatorVersion, b.SimulatorVersion),
		strings.Compare(a.ProductVersionExtra, b.ProductVersionExtra),
		strings.Compare(a.Build, b.Build),
		strings.Compare(a.AssetType, b.AssetType),
		cmp.Compare(boolRank(a.SplatOnly), boolRank(b.SplatOnly)),
		strings.Compare(a.PrerequisiteBuild, b.PrerequisiteBuild),
		strings.Compare(a.PrerequisiteOSVersion, b.PrerequisiteOSVersion),
		strings.Compare(a.DocumentationID, b.DocumentationID),
		strings.Compare(a.ReleaseType, b.ReleaseType),
		strings.Compare(a.TrainName, b.TrainName),
		cmp.Compare(a.DownloadSize, b.DownloadSize),
		cmp.Compare(a.UnarchivedSize, b.UnarchivedSize),
		strings.Compare(a.HashAlgorithm, b.HashAlgorithm),
		bytes.Compare(a.Hash, b.Hash),
		bytes.Compare(a.Sha256Hash, b.Sha256Hash),
		cmp.Compare(boolRank(a.IsEncrypted), boolRank(b.IsEncrypted)),
		strings.Compare(a.AssetFormat, b.AssetFormat),
		strings.Compare(a.ArchiveDecryptionKey, b.ArchiveDecryptionKey),
		compareOptionalBool(OTAIsSeed(a), OTAIsSeed(b)),
		strings.Compare(a.BaseURL, b.BaseURL),
		strings.Compare(a.RelativePath, b.RelativePath),
		slices.Compare(a.SupportedDevices, b.SupportedDevices),
		slices.Compare(a.SupportedDeviceModels, b.SupportedDeviceModels),
	)
}

func otaSourceRank(source string) int {
	switch source {
	case OTASourcePallas:
		return 0
	case OTASourceMesu:
		return 1
	}
	return 2
}

func otaAudienceRankOf(name string) int {
	if rank, ok := otaAudienceRank[name]; ok {
		return rank
	}
	return len(otaAudienceRank)
}

func compareOptionalBool(a, b *bool) int {
	return cmp.Compare(optionalBoolRank(a), optionalBoolRank(b))
}

func optionalBoolRank(v *bool) int {
	switch {
	case v == nil:
		return 0
	case !*v:
		return 1
	}
	return 2
}

func boolRank(v bool) int {
	if v {
		return 1
	}
	return 0
}

func sortedUniqueStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ClassifyOTAChannel returns the one channel supported by all resolver
// evidence. Every real sighting must decide; conflicting or undecided evidence
// fails closed to unknown. A marker-free canonical asset may abstain.
func ClassifyOTAChannel(record OTARecord) string {
	consensus := otaChannelAbstain
	for _, sighting := range record.Sightings {
		vote := classifyOTASighting(sighting)
		if vote == otaChannelAbstain {
			return OTAChannelUnknown
		}
		consensus = mergeOTAChannelVotes(consensus, vote)
	}
	consensus = mergeOTAChannelVotes(consensus, classifyOTASighting(otaAssetSighting(record.Asset)))
	if consensus == otaChannelAbstain {
		return OTAChannelUnknown
	}
	return consensus
}

// mergeOTAChannelVotes folds one vote into the running consensus. An abstaining
// vote changes nothing, agreement keeps the kind, and any disagreement
// (including an unknown vote) fails closed to unknown, which then absorbs
// every later vote.
func mergeOTAChannelVotes(consensus, vote string) string {
	switch {
	case vote == otaChannelAbstain:
		return consensus
	case consensus == otaChannelAbstain:
		return vote
	case consensus == vote:
		return consensus
	default:
		return OTAChannelUnknown
	}
}

func classifyOTASighting(sighting OTASighting) string {
	switch {
	case otaRCDocumentationID.MatchString(sighting.DocumentationID):
		return OTAChannelRC
	case sighting.ReleaseType == "Beta", strings.Contains(sighting.DocumentationID, "Beta"):
		return OTAChannelBeta
	case sighting.ReleaseType != "", sighting.IsSeed != nil && *sighting.IsSeed:
		return OTAChannelUnknown
	case sighting.Source == OTASourceMesu:
		return OTAChannelRelease
	case sighting.Source == OTASourcePallas && otaReleaseAudience(sighting.AudienceName):
		return OTAChannelRelease
	default:
		return otaChannelAbstain
	}
}

func otaAssetSighting(asset types.Asset) OTASighting {
	return OTASighting{
		OSVersion:       asset.OSVersion,
		Build:           asset.Build,
		DocumentationID: asset.DocumentationID,
		ReleaseType:     asset.ReleaseType,
		IsSeed:          OTAIsSeed(asset),
	}
}

func otaReleaseAudience(name string) bool {
	switch name {
	case OTAAudienceRelease, OTAAudienceAlternate, OTAAudienceGeneric:
		return true
	default:
		return false
	}
}

type otaAudienceLabel struct {
	name    string
	version string
}

// otaAudienceLabels inverts the embedded audience database. Platforms are
// visited in sorted order so an ID shared between entries always resolves to
// the same label.
func otaAudienceLabels(db AssetAudienceIDs) map[string]otaAudienceLabel {
	labels := make(map[string]otaAudienceLabel)
	add := func(id, name, version string) {
		if id == "" {
			return
		}
		if _, seen := labels[id]; !seen {
			labels[id] = otaAudienceLabel{name: name, version: version}
		}
	}
	for _, platform := range slices.Sorted(maps.Keys(db)) {
		entry := db[platform]
		add(entry.Release, OTAAudienceRelease, "")
		add(entry.Alternate, OTAAudienceAlternate, "")
		add(entry.Generic, OTAAudienceGeneric, "")
		for _, version := range slices.Sorted(maps.Keys(entry.Versions)) {
			seeds := entry.Versions[version]
			add(seeds.DeveloperBeta, OTAAudienceDeveloperBeta, version)
			add(seeds.AppleSeedBeta, OTAAudienceAppleSeedBeta, version)
			add(seeds.PublicBeta, OTAAudiencePublicBeta, version)
		}
	}
	return labels
}

// MatchBuild returns every pmv entry whose build matches, in list order
// (PublicAssetSets, AssetSets, PublicBackgroundSecurityImprovements) and then
// sorted OS key order. A nil receiver or empty build matches nothing.
func (a *AssetSets) MatchBuild(build string) []OTAAssetSetMatch {
	if a == nil || build == "" {
		return nil
	}
	var matches []OTAAssetSetMatch
	for _, list := range otaAssetSetLists {
		sets := a.listByName(list)
		for _, os := range slices.Sorted(maps.Keys(sets)) {
			for _, set := range sets[os] {
				if !strings.EqualFold(set.Build, build) {
					continue
				}
				match := OTAAssetSetMatch{
					List:                list,
					OS:                  os,
					ProductVersion:      set.ProductVersion,
					ProductVersionExtra: set.ProductVersionExtra,
					Build:               set.Build,
					PrerequisiteBuild:   set.PrerequisiteBuild,
					PostingDate:         set.PostingDate,
					ExpirationDate:      set.ExpirationDate,
				}
				if !slices.Contains(matches, match) {
					matches = append(matches, match)
				}
			}
		}
	}
	return matches
}

func (a *AssetSets) listByName(list string) map[string][]AssetSet {
	switch list {
	case OTAAssetSetListPublic:
		return a.PublicAssetSets
	case otaAssetSetListInternal:
		return a.AssetSets
	case otaAssetSetListBackground:
		return a.PublicBackgroundSecurityImprovements
	}
	return nil
}
