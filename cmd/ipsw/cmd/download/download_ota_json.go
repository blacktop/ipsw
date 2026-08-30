package download

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/ota/types"
)

const otaJSONSchemaVersion = 1

type otaJSONEnvelope struct {
	SchemaVersion int            `json:"schema_version"`
	OTAs          []otaJSONAsset `json:"otas"`
}

type otaJSONAsset struct {
	OS               *string              `json:"os"`
	Version          *string              `json:"version"`
	VersionExtra     *string              `json:"version_extra"`
	Build            *string              `json:"build"`
	Channel          otaJSONChannel       `json:"channel"`
	PostingDate      *string              `json:"posting_date"`
	Delivery         string               `json:"delivery"`
	Prerequisite     *otaJSONPrerequisite `json:"prerequisite"`
	SupportedDevices []string             `json:"supported_devices"`
	SupportedModels  []string             `json:"supported_models"`
	URL              string               `json:"url"`
	DownloadSize     *int64               `json:"download_size"`
	UnarchivedSize   *int64               `json:"unarchived_size"`
	SHA1             *string              `json:"sha1"`
	SHA256           *string              `json:"sha256"`
	Encryption       otaJSONEncryption    `json:"encryption"`
	Provenance       otaJSONProvenance    `json:"provenance"`
}

type otaJSONChannel struct {
	Kind            string            `json:"kind"`
	ReleaseType     *string           `json:"release_type"`
	DocumentationID *string           `json:"documentation_id"`
	TrainName       *string           `json:"train_name"`
	IsSeed          *bool             `json:"is_seed"`
	Audiences       []otaJSONAudience `json:"audiences"`
}

type otaJSONAudience struct {
	ID      string  `json:"id"`
	Name    *string `json:"name"`
	Version *string `json:"version"`
}

type otaJSONPrerequisite struct {
	Build   string  `json:"build"`
	Version *string `json:"version"`
}

type otaJSONEncryption struct {
	Encrypted    bool    `json:"encrypted"`
	Format       *string `json:"format"`
	KeyAvailable bool    `json:"decryption_key_available"`
}

type otaJSONProvenance struct {
	AssetType *string           `json:"asset_type"`
	Sightings []otaJSONSighting `json:"sightings"`
	AssetSets []otaJSONAssetSet `json:"asset_sets"`
}

type otaJSONSighting struct {
	Source          string  `json:"source"`
	AudienceID      *string `json:"audience_id"`
	AssetSetID      *string `json:"asset_set_id"`
	PostingDate     *string `json:"posting_date"`
	Build           *string `json:"build"`
	DocumentationID *string `json:"documentation_id"`
	ReleaseType     *string `json:"release_type"`
	IsSeed          *bool   `json:"is_seed"`
}

type otaJSONAssetSet struct {
	List                string  `json:"list"`
	OS                  string  `json:"os"`
	ProductVersion      string  `json:"product_version"`
	ProductVersionExtra *string `json:"product_version_extra"`
	Build               string  `json:"build"`
	PrerequisiteBuild   *string `json:"prerequisite_build"`
	PostingDate         *string `json:"posting_date"`
	ExpirationDate      *string `json:"expiration_date"`
}

// newOTAJSONEnvelope renders records unique per URL in deterministic order.
// Records without a URL are not downloadable and are omitted, matching the
// resolver's own selection.
func newOTAJSONEnvelope(records []download.OTARecord) otaJSONEnvelope {
	envelope := otaJSONEnvelope{
		SchemaVersion: otaJSONSchemaVersion,
		OTAs:          make([]otaJSONAsset, 0, len(records)),
	}
	sorted := slices.Clone(records)
	download.SortOTARecords(sorted)
	indexes := make(map[string]int)
	for _, record := range sorted {
		url := download.OTAURL(record.Asset)
		if url == "" {
			continue
		}
		if idx, seen := indexes[url]; seen {
			existing := &envelope.OTAs[idx]
			existing.SupportedDevices = otaSortedUnique(existing.SupportedDevices, record.Devices, record.Asset.SupportedDevices)
			existing.SupportedModels = otaSortedUnique(existing.SupportedModels, record.Models, record.Asset.SupportedDeviceModels)
			continue
		}
		indexes[url] = len(envelope.OTAs)
		envelope.OTAs = append(envelope.OTAs, newOTAJSONAsset(record))
	}
	return envelope
}

func writeOTAJSON(w io.Writer, records []download.OTARecord) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(newOTAJSONEnvelope(records)); err != nil {
		return fmt.Errorf("failed to marshal json: %v", err)
	}
	return nil
}

func newOTAJSONAsset(record download.OTARecord) otaJSONAsset {
	asset := record.Asset
	representative := otaRepresentativeSighting(record)
	return otaJSONAsset{
		OS:               otaOptionalString(asset.ProductSystemName),
		Version:          otaOptionalString(download.OTAVersion(asset)),
		VersionExtra:     otaOptionalString(asset.ProductVersionExtra),
		Build:            otaOptionalString(asset.Build),
		Channel:          newOTAJSONChannel(record, representative),
		PostingDate:      otaAgreedPostingDate(record),
		Delivery:         download.OTADelivery(asset),
		Prerequisite:     newOTAJSONPrerequisite(asset),
		SupportedDevices: otaSortedUnique(record.Devices, asset.SupportedDevices),
		SupportedModels:  otaSortedUnique(record.Models, asset.SupportedDeviceModels),
		URL:              download.OTAURL(asset),
		DownloadSize:     otaOptionalSize(asset.DownloadSize),
		UnarchivedSize:   otaOptionalSize(asset.UnarchivedSize),
		SHA1:             otaSHA1(asset),
		SHA256:           otaSHA256(asset),
		Encryption: otaJSONEncryption{
			Encrypted:    asset.IsEncrypted || asset.ArchiveDecryptionKey != "",
			Format:       otaOptionalString(asset.AssetFormat),
			KeyAvailable: asset.ArchiveDecryptionKey != "",
		},
		Provenance: newOTAJSONProvenance(record),
	}
}

// otaRepresentativeSighting is the highest-ranked sighting for the canonical
// asset, or the asset's own markers when no sighting matches it.
func otaRepresentativeSighting(record download.OTARecord) download.OTASighting {
	for _, sighting := range record.Sightings {
		if otaSightingMatchesAsset(sighting, record.Asset) {
			return sighting
		}
	}
	return otaAssetSighting(record.Asset)
}

func otaSightingMatchesAsset(sighting download.OTASighting, asset types.Asset) bool {
	if sighting.OSVersion != asset.OSVersion || sighting.Build != asset.Build ||
		sighting.DocumentationID != asset.DocumentationID || sighting.ReleaseType != asset.ReleaseType {
		return false
	}
	assetSeed := download.OTAIsSeed(asset)
	if sighting.IsSeed == nil || assetSeed == nil {
		return sighting.IsSeed == nil && assetSeed == nil
	}
	return *sighting.IsSeed == *assetSeed
}

// otaAssetSighting exposes the resolved asset's own markers as evidence with
// no source or audience, so it can only vote beta or rc, never release.
func otaAssetSighting(asset types.Asset) download.OTASighting {
	return download.OTASighting{
		OSVersion:       asset.OSVersion,
		Build:           asset.Build,
		DocumentationID: asset.DocumentationID,
		ReleaseType:     asset.ReleaseType,
		IsSeed:          download.OTAIsSeed(asset),
	}
}

func newOTAJSONChannel(record download.OTARecord, representative download.OTASighting) otaJSONChannel {
	channel := otaJSONChannel{
		Kind:            download.ClassifyOTAChannel(record),
		ReleaseType:     otaOptionalString(representative.ReleaseType),
		DocumentationID: otaOptionalString(representative.DocumentationID),
		TrainName:       otaOptionalString(record.Asset.TrainName),
		IsSeed:          representative.IsSeed,
		Audiences:       make([]otaJSONAudience, 0),
	}
	for _, sighting := range record.Sightings {
		if sighting.AudienceID == "" {
			continue
		}
		if slices.ContainsFunc(channel.Audiences, func(a otaJSONAudience) bool { return a.ID == sighting.AudienceID }) {
			continue
		}
		channel.Audiences = append(channel.Audiences, otaJSONAudience{
			ID:      sighting.AudienceID,
			Name:    otaOptionalString(sighting.AudienceName),
			Version: otaOptionalString(sighting.AudienceVersion),
		})
	}
	return channel
}

// otaAgreedPostingDate returns the posting date only when every primary date
// supplied by Pallas and PublicAssetSets agrees. Other PMV lists remain in
// provenance but do not override the public release date.
func otaAgreedPostingDate(record download.OTARecord) *string {
	var dates []string
	for _, sighting := range record.Sightings {
		if sighting.Source == download.OTASourcePallas {
			dates = append(dates, sighting.PostingDate)
		}
	}
	for _, set := range record.AssetSets {
		if set.List == download.OTAAssetSetListPublic {
			dates = append(dates, set.PostingDate)
		}
	}
	dates = otaSortedUnique(dates)
	if len(dates) != 1 {
		return nil
	}
	return &dates[0]
}

func newOTAJSONPrerequisite(asset types.Asset) *otaJSONPrerequisite {
	if asset.PrerequisiteBuild == "" {
		return nil
	}
	return &otaJSONPrerequisite{
		Build:   asset.PrerequisiteBuild,
		Version: otaOptionalString(strings.TrimPrefix(asset.PrerequisiteOSVersion, "9.9.")),
	}
}

func newOTAJSONProvenance(record download.OTARecord) otaJSONProvenance {
	provenance := otaJSONProvenance{
		AssetType: otaOptionalString(record.Asset.AssetType),
		Sightings: make([]otaJSONSighting, 0, len(record.Sightings)),
		AssetSets: make([]otaJSONAssetSet, 0, len(record.AssetSets)),
	}
	for _, sighting := range record.Sightings {
		provenance.Sightings = append(provenance.Sightings, otaJSONSighting{
			Source:          sighting.Source,
			AudienceID:      otaOptionalString(sighting.AudienceID),
			AssetSetID:      otaOptionalString(sighting.AssetSetID),
			PostingDate:     otaOptionalString(sighting.PostingDate),
			Build:           otaOptionalString(sighting.Build),
			DocumentationID: otaOptionalString(sighting.DocumentationID),
			ReleaseType:     otaOptionalString(sighting.ReleaseType),
			IsSeed:          sighting.IsSeed,
		})
	}
	for _, match := range record.AssetSets {
		provenance.AssetSets = append(provenance.AssetSets, otaJSONAssetSet{
			List:                match.List,
			OS:                  match.OS,
			ProductVersion:      match.ProductVersion,
			ProductVersionExtra: otaOptionalString(match.ProductVersionExtra),
			Build:               match.Build,
			PrerequisiteBuild:   otaOptionalString(match.PrerequisiteBuild),
			PostingDate:         otaOptionalString(match.PostingDate),
			ExpirationDate:      otaOptionalString(match.ExpirationDate),
		})
	}
	return provenance
}

// otaSHA1 reports the SHA-1 measurement only when Apple labeled it as such.
func otaSHA1(asset types.Asset) *string {
	algorithm := strings.ToUpper(strings.ReplaceAll(asset.HashAlgorithm, "-", ""))
	if algorithm != "SHA1" || len(asset.Hash) != sha1.Size {
		return nil
	}
	digest := hex.EncodeToString(asset.Hash)
	return &digest
}

func otaSHA256(asset types.Asset) *string {
	measurement := asset.Sha256Hash
	if len(measurement) != sha256.Size {
		algorithm := strings.ToUpper(strings.ReplaceAll(asset.HashAlgorithm, "-", ""))
		if algorithm != "SHA256" || len(asset.Hash) != sha256.Size {
			return nil
		}
		measurement = asset.Hash
	}
	digest := hex.EncodeToString(measurement)
	return &digest
}

func otaOptionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// otaOptionalSize treats a zero size as unsupplied: Apple's payload decodes
// into an int without presence information and a zero-byte OTA does not exist.
func otaOptionalSize(size int) *int64 {
	if size <= 0 {
		return nil
	}
	value := int64(size)
	return &value
}

func otaSortedUnique(lists ...[]string) []string {
	out := make([]string, 0)
	for _, list := range lists {
		for _, value := range list {
			if value != "" {
				out = append(out, value)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
