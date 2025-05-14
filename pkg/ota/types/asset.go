package types

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/dustin/go-humanize"
)

type bridgeVersionInfo struct {
	BridgeBuildGroup          string `json:"BridgeBuildGroup,omitempty"`
	BridgeProductBuildVersion string `json:"BridgeProductBuildVersion,omitempty"`
	BridgeVersion             string `json:"BridgeVersion,omitempty"`
	CatalogURL                string `json:"CatalogURL,omitempty"`
	IsSeed                    string `json:"IsSeed,omitempty"`
	SEPEpoch                  struct {
		Major int `json:"Major,omitempty"`
		Minor int `json:"Minor,omitempty"`
	} `json:"SEPEpoch"`
}

type restoreVersionInfo struct {
	IsSeed             bool   `json:"IsSeed,omitempty"`
	RestoreBuildGroup  any    `json:"RestoreBuildGroup,omitempty"`
	RestoreLongVersion string `json:"RestoreLongVersion,omitempty"`
	RestoreVersion     string `json:"RestoreVersion,omitempty"`
}

type assetReceipt struct {
	AssetReceipt   string `json:"AssetReceipt"`
	AssetSignature string `json:"AssetSignature"`
}

type cryptexSize struct {
	CryptexSize int    `json:"CryptexSize,omitempty"`
	CryptexTag  string `json:"CryptexTag,omitempty"`
}

// Asset is an OTA asset object
type Asset struct {
	ActualMinimumSystemPartition          int                `json:"ActualMinimumSystemPartition" plist:"ActualMinimumSystemPartition,omitempty"`
	AutoUpdate                            bool               `json:"AutoUpdate" plist:"AutoUpdate,omitempty"`
	AssetType                             string             `json:"AssetType" plist:"AssetType,omitempty"`
	BridgeVersionInfo                     bridgeVersionInfo  `json:"BridgeVersionInfo" plist:"BridgeVersionInfo,omitempty"`
	Build                                 string             `json:"Build" plist:"Build,omitempty"`
	SimulatorVersion                      string             `json:"SimulatorVersion" plist:"SimulatorVersion,omitempty"`
	DataTemplateSize                      int                `json:"DataTemplateSize" plist:"DataTemplateSize,omitempty"`
	EAPFSEnabled                          bool               `json:"EAPFSEnabled,omitempty" plist:"EAPFSEnabled,omitempty"`
	InstallationSize                      string             `json:"InstallationSize" plist:"InstallationSize,omitempty"`
	InstallationSizeSnapshot              string             `json:"InstallationSize-Snapshot" plist:"InstallationSize-Snapshot,omitempty"`
	MinimumSystemPartition                int                `json:"MinimumSystemPartition" plist:"MinimumSystemPartition,omitempty"`
	OSVersion                             string             `json:"OSVersion" plist:"OSVersion,omitempty"`
	PreflightBuildManifest                []byte             `json:"PreflightBuildManifest" plist:"PreflightBuildManifest,omitempty"`
	PreflightGlobalSignatures             []byte             `json:"PreflightGlobalSignatures" plist:"PreflightGlobalSignatures,omitempty"`
	RestoreVersion                        string             `json:"RestoreVersion,omitempty" plist:"RestoreVersion,omitempty"`
	RestoreVersionInfo                    restoreVersionInfo `json:"RestoreVersionInfo" plist:"RestoreVersionInfo,omitempty"`
	PrerequisiteBuild                     string             `json:"PrerequisiteBuild" plist:"PrerequisiteBuild,omitempty"`
	PrerequisiteOSVersion                 string             `json:"PrerequisiteOSVersion" plist:"PrerequisiteOSVersion,omitempty"`
	ProductVersionExtra                   string             `json:"ProductVersionExtra" plist:"ProductVersionExtra,omitempty"`
	RSEPDigest                            []byte             `json:"RSEPDigest" plist:"RSEPDigest,omitempty"`
	Ramp                                  bool               `json:"Ramp" plist:"Ramp,omitempty"`
	RescueMinimumSystemPartition          int                `json:"RescueMinimumSystemPartition" plist:"RescueMinimumSystemPartition,omitempty"`
	SEPDigest                             []byte             `json:"SEPDigest" plist:"SEPDigest,omitempty"`
	ConvReqd                              bool               `json:"SUConvReqd" plist:"SUConvReqd,omitempty"`
	DocumentationID                       string             `json:"SUDocumentationID" plist:"SUDocumentationID,omitempty"`
	ReleaseType                           string             `json:"ReleaseType" plist:"ReleaseType,omitempty"`
	InstallTonightEnabled                 bool               `json:"SUInstallTonightEnabled" plist:"SUInstallTonightEnabled,omitempty"`
	MultiPassEnabled                      bool               `json:"SUMultiPassEnabled" plist:"SUMultiPassEnabled,omitempty"`
	ProductSystemName                     string             `json:"SUProductSystemName" plist:"SUProductSystemName,omitempty"`
	Publisher                             string             `json:"SUPublisher" plist:"SUPublisher,omitempty"`
	SplatOnly                             bool               `json:"SplatOnly" plist:"SplatOnly,omitempty"`
	SupportedDeviceModels                 []string           `json:"SupportedDeviceModels" plist:"SupportedDeviceModels,omitempty"`
	SupportedDevices                      []string           `json:"SupportedDevices" plist:"SupportedDevices,omitempty"`
	SystemPartitionPadding                map[string]int     `json:"SystemPartitionPadding" plist:"SystemPartitionPadding,omitempty"`
	SystemVolumeSealingOverhead           int                `json:"SystemVolumeSealingOverhead" plist:"SystemVolumeSealingOverhead,omitempty"`
	TargetUpdateBridgeVersion             string             `json:"TargetUpdateBridgeVersion" plist:"TargetUpdateBridgeVersion,omitempty"`
	AssetReceipt                          assetReceipt       `json:"_AssetReceipt" plist:"_AssetReceipt,omitempty"`
	CompressionAlgorithm                  string             `json:"_CompressionAlgorithm" plist:"_CompressionAlgorithm,omitempty"`
	DownloadSize                          int                `json:"_DownloadSize" plist:"_DownloadSize,omitempty"`
	EventRecordingServiceURL              string             `json:"_EventRecordingServiceURL" plist:"_EventRecordingServiceURL,omitempty"`
	IsZipStreamable                       bool               `json:"_IsZipStreamable" plist:"_IsZipStreamable,omitempty"`
	MasteredVersion                       string             `json:"_MasteredVersion" plist:"_MasteredVersion,omitempty"`
	Hash                                  []byte             `json:"_Measurement" plist:"_Measurement,omitempty"`
	Sha256Hash                            []byte             `json:"_Measurement-SHA256" plist:"_Measurement-SHA256,omitempty"`
	HashAlgorithm                         string             `json:"_MeasurementAlgorithm" plist:"_MeasurementAlgorithm,omitempty"`
	UnarchivedSize                        int                `json:"_UnarchivedSize" plist:"_UnarchivedSize,omitempty"`
	AssetDefaultGarbageCollectionBehavior string             `json:"__AssetDefaultGarbageCollectionBehavior" plist:"__AssetDefaultGarbageCollectionBehavior,omitempty"`
	BaseURL                               string             `json:"__BaseURL" plist:"__BaseURL,omitempty"`
	CanUseLocalCacheServer                bool               `json:"__CanUseLocalCacheServer" plist:"__CanUseLocalCacheServer,omitempty"`
	HideInstallAlert                      bool               `json:"__HideInstallAlert" plist:"__HideInstallAlert,omitempty"`
	QueuingServiceURL                     string             `json:"__QueuingServiceURL" plist:"__QueuingServiceURL,omitempty"`
	RelativePath                          string             `json:"__RelativePath" plist:"__RelativePath,omitempty"`
	// extras
	DeviceName                           string `json:"DeviceName,omitempty" plist:"DeviceName,omitempty"`
	FirmwareBundle                       string `json:"FirmwareBundle,omitempty" plist:"FirmwareBundle,omitempty"`
	FirmwareVersionMajor                 int    `json:"FirmwareVersionMajor,omitempty" plist:"FirmwareVersionMajor,omitempty"`
	FirmwareVersionMinor                 int    `json:"FirmwareVersionMinor,omitempty" plist:"FirmwareVersionMinor,omitempty"`
	FirmwareVersionRelease               int    `json:"FirmwareVersionRelease,omitempty" plist:"FirmwareVersionRelease,omitempty"`
	Devices                              []string
	DisablePreSoftwareUpdateAssetStaging bool          `json:"DisablePreSoftwareUpdateAssetStaging,omitempty" plist:"DisablePreSoftwareUpdateAssetStaging,omitempty"`
	TrainName                            string        `json:"TrainName,omitempty" plist:"TrainName,omitempty"`
	ArchiveID                            string        `json:"ArchiveID,omitempty" plist:"ArchiveID,omitempty"`
	AssetFormat                          string        `json:"AssetFormat,omitempty" plist:"AssetFormat,omitempty"`
	IsEncrypted                          bool          `json:"_IsEncrypted,omitempty" plist:"_IsEncrypted,omitempty"`
	ArchiveDecryptionKey                 string        `json:"ArchiveDecryptionKey,omitempty" plist:"ArchiveDecryptionKey,omitempty"`
	CryptexSizeInfo                      []cryptexSize `json:"CryptexSizeInfo,omitempty" plist:"CryptexSizeInfo,omitempty"`
}

func (a Asset) Version() string {
	if len(a.ProductVersionExtra) > 0 {
		return fmt.Sprintf("%s %s", strings.TrimPrefix(a.OSVersion, "9.9."), a.ProductVersionExtra)
	}
	return strings.TrimPrefix(a.OSVersion, "9.9.")
}

func (a Asset) String() string {
	var prereq string
	if len(a.PrerequisiteBuild) > 0 {
		prereq = fmt.Sprintf(", prereq_version: %s (%s)", a.PrerequisiteOSVersion, a.PrerequisiteBuild)
	}
	var version string
	if len(a.RestoreVersion) > 0 {
		version = fmt.Sprintf(", version: %s", a.RestoreVersion)
	}
	var key string
	if a.IsEncrypted {
		key = fmt.Sprintf(", encrypted: %t key: 'base64:%s'", a.IsEncrypted, a.ArchiveDecryptionKey)
	}
	return fmt.Sprintf("name: %s%s, build: %s, os: %s, asset_type: %s%s, devices: %d, models: %d, size: %s, zip: %s%s",
		a.DocumentationID,
		version,
		a.Build,
		a.OSVersion,
		a.AssetType,
		prereq,
		len(a.SupportedDevices),
		len(a.SupportedDeviceModels),
		humanize.Bytes(uint64(a.UnarchivedSize)),
		filepath.Base(a.RelativePath),
		key,
	)
}

func (a Asset) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		URL           string   `json:"url,omitempty"`
		Description   string   `json:"description,omitempty"`
		Product       string   `json:"product,omitempty"`
		Devices       []string `json:"devices,omitempty"`
		Version       string   `json:"version,omitempty"`
		Build         string   `json:"build,omitempty"`
		Size          string   `json:"size,omitempty"`
		Type          string   `json:"type,omitempty"`
		Hash          string   `json:"hash,omitempty"`
		HashAlgorithm string   `json:"hash_algorithm,omitempty"`
		IsEncrypted   bool     `json:"encrypted,omitempty"`
		Key           string   `json:"key,omitempty"`
	}{
		URL:           a.BaseURL + a.RelativePath,
		Description:   a.DocumentationID,
		Product:       a.ProductSystemName,
		Devices:       a.Devices,
		Version:       a.Version(),
		Build:         a.Build,
		Size:          humanize.Bytes(uint64(a.DownloadSize)),
		Type:          a.ReleaseType,
		Hash:          hex.EncodeToString(a.Hash),
		HashAlgorithm: a.HashAlgorithm,
		IsEncrypted:   a.IsEncrypted,
		Key:           a.ArchiveDecryptionKey,
	})
}
