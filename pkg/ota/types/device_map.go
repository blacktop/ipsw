package types

import (
	"bytes"
	"fmt"

	"github.com/blacktop/go-plist"
)

// DeviceMap is an OTA device map object
type DeviceMap map[string]*Device

// Device is an OTA device object
type Device struct {
	ANE1FirmwareType              string         `plist:"ANE1FirmwareType,omitempty"`
	ANEFirmwareType               string         `plist:"ANEFirmwareType,omitempty"`
	ANS2FirmwareType              string         `plist:"ANS2FirmwareType,omitempty"`
	AOPFirmwareType               string         `plist:"AOPFirmwareType,omitempty"`
	AcousticId                    string         `plist:"AcousticId,omitempty"`
	AllowSDKPlatformFallback      bool           `plist:"AllowSDKPlatformFallback,omitempty"`
	ArtworkDeviceIdiom            string         `plist:"ArtworkDeviceIdiom,omitempty"`
	ArtworkDeviceSubtype          string         `plist:"ArtworkDeviceSubtype,omitempty"`
	ArtworkDisplayGamut           string         `plist:"ArtworkDisplayGamut,omitempty"`
	ArtworkScaleFactor            string         `plist:"ArtworkScaleFactor,omitempty"`
	AudioChimeType                string         `plist:"AudioChimeType,omitempty"`
	BMUBoardID                    string         `plist:"BMU,BoardID,omitempty"`
	BMUChipID                     string         `plist:"BMU,ChipID,omitempty"`
	BasebandChipID                string         `plist:"BasebandChipID,omitempty"`
	BbActivationManifestKeyHash   []byte         `plist:"BbActivationManifestKeyHash,omitempty"`
	BbCanFuse                     bool           `plist:"BbCanFuse,omitempty"`
	BbCanPersonalizeLocally       bool           `plist:"BbCanPersonalizeLocally,omitempty"`
	BbCanPersonalizeWithServer    bool           `plist:"BbCanPersonalizeWithServer,omitempty"`
	BbCanUpdate                   bool           `plist:"BbCanUpdate,omitempty"`
	BbFDRSecurityKeyHash          []byte         `plist:"BbFDRSecurityKeyHash,omitempty"`
	BbFirmwareInSystemPartition   bool           `plist:"BbFirmwareInSystemPartition,omitempty"`
	BbProvisioningManifestKeyHash []byte         `plist:"BbProvisioningManifestKeyHash,omitempty"`
	BitmapType                    string         `plist:"BitmapType,omitempty"`
	BoardID                       string         `plist:"BoardID,omitempty"`
	BuildVariants                 any            `plist:"BuildVariants,omitempty"`
	CIOFirmwareType               string         `plist:"CIOFirmwareType,omitempty"`
	ChipID                        string         `plist:"ChipID,omitempty"`
	CompatibleAppVariant          string         `plist:"CompatibleAppVariant,omitempty"`
	CompatibleFallbackProductType string         `plist:"CompatibleFallbackProductType,omitempty"`
	ConserveBootFlash             bool           `plist:"ConserveBootFlash,omitempty"`
	CoprocessorProperties         string         `plist:"CoprocessorProperties,omitempty"`
	CryptoHashMethod              string         `plist:"CryptoHashMethod,omitempty"`
	DCPFirmwareType               string         `plist:"DCPFirmwareType,omitempty"`
	DevicePerformanceMemoryClass  string         `plist:"DevicePerformanceMemoryClass,omitempty"`
	DiagsFile                     string         `plist:"DiagsFile,omitempty"`
	DiagsProject                  string         `plist:"DiagsProject,omitempty"`
	DisableAOP                    bool           `plist:"DisableAOP,omitempty"`
	EnableANE                     bool           `plist:"EnableANE,omitempty"`
	EnableANE1                    bool           `plist:"EnableANE1,omitempty"`
	EnableANE2                    bool           `plist:"EnableANE2,omitempty"`
	EnableANE3                    bool           `plist:"EnableANE3,omitempty"`
	EnableANS2                    bool           `plist:"EnableANS2,omitempty"`
	EnableCIO                     bool           `plist:"EnableCIO,omitempty"`
	EnableDCP                     bool           `plist:"EnableDCP,omitempty"`
	EnableGFX                     bool           `plist:"EnableGFX,omitempty"`
	EnableISP                     bool           `plist:"EnableISP,omitempty"`
	EnablePMP                     bool           `plist:"EnablePMP,omitempty"`
	EnableTMU                     bool           `plist:"EnableTMU,omitempty"`
	FDRAllowClaimFailure          bool           `plist:"FDRAllowClaimFailure,omitempty"`
	FDRSupport                    bool           `plist:"FDRSupport,omitempty"`
	FUDUsesiBootLoading           bool           `plist:"FUDUsesiBootLoading,omitempty"`
	GFXFirmwareType               string         `plist:"GFXFirmwareType,omitempty"`
	GPUPipeline                   string         `plist:"GPUPipeline,omitempty"`
	GraphicsFeatureSetClass       string         `plist:"GraphicsFeatureSetClass,omitempty"`
	GraphicsFeatureSetFallbacks   string         `plist:"GraphicsFeatureSetFallbacks,omitempty"`
	HasACI                        bool           `plist:"HasACI,omitempty"`
	HasBootChime                  bool           `plist:"HasBootChime,omitempty"`
	HasExternalSensorModule1      bool           `plist:"HasExternalSensorModule1,omitempty"`
	HasFUDPhleet                  bool           `plist:"HasFUDPhleet,omitempty"`
	HasHapticAssets               bool           `plist:"HasHapticAssets,omitempty"`
	HasHomer                      bool           `plist:"HasHomer,omitempty"`
	HasIOExtensionModule1         bool           `plist:"HasIOExtensionModule1,omitempty"`
	HasIOHubMaster                bool           `plist:"HasIOHubMaster,omitempty"`
	HasIOHubSlave                 bool           `plist:"HasIOHubSlave,omitempty"`
	HasInputDevice                bool           `plist:"HasInputDevice,omitempty"`
	HasLeapHaptics                bool           `plist:"HasLeapHaptics,omitempty"`
	HasLiquidDetection            bool           `plist:"HasLiquidDetection,omitempty"`
	HasLowPowerExpressMode        bool           `plist:"HasLowPowerExpressMode,omitempty"`
	HasLowPowerFindMyMode         bool           `plist:"HasLowPowerFindMyMode,omitempty"`
	HasLpemBT                     bool           `plist:"HasLpemBT,omitempty"`
	HasMConnector                 bool           `plist:"HasMConnector,omitempty"`
	HasMTP                        bool           `plist:"HasMTP,omitempty"`
	HasMacEFIFirmware             bool           `plist:"HasMacEFIFirmware,omitempty"`
	HasPowerAttachChime           bool           `plist:"HasPowerAttachChime,omitempty"`
	HasRTP                        bool           `plist:"HasRTP,omitempty"`
	HasRTPDarwin                  bool           `plist:"HasRTPDarwin,omitempty"`
	HasRestoreRTP                 bool           `plist:"HasRestoreRTP,omitempty"`
	HasRoseSEPairing              bool           `plist:"HasRoseSEPairing,omitempty"`
	HasSCE                        bool           `plist:"HasSCE,omitempty"`
	HasSCE1                       bool           `plist:"HasSCE1,omitempty"`
	HasSiValAlias                 bool           `plist:"HasSiValAlias,omitempty"`
	HasSoftwareBinaryDsp2         bool           `plist:"HasSoftwareBinaryDsp2,omitempty"`
	HasVendorBuild                bool           `plist:"HasVendorBuild,omitempty"`
	HasWirelessPowerFirmware      bool           `plist:"HasWirelessPowerFirmware,omitempty"`
	HibernationSupport            bool           `plist:"HibernationSupport,omitempty"`
	ISPFirmwareType               string         `plist:"ISPFirmwareType,omitempty"`
	ImageFormat                   string         `plist:"ImageFormat,omitempty"`
	InternalTarget                bool           `plist:"InternalTarget,omitempty"`
	IsHosted                      bool           `plist:"IsHosted,omitempty"`
	IsVirtualPlatform             bool           `plist:"IsVirtualPlatform,omitempty"`
	KernelCacheType               string         `plist:"KernelCacheType,omitempty"`
	KernelMachOArchitecture       string         `plist:"KernelMachOArchitecture,omitempty"`
	KernelPlatform                string         `plist:"KernelPlatform,omitempty"`
	KernelType                    string         `plist:"KernelType,omitempty"`
	MLBType                       string         `plist:"MLBType,omitempty"`
	MTPProject                    string         `plist:"MTPProject,omitempty"`
	MacEFIFirmwareType            string         `plist:"MacEFIFirmwareType,omitempty"`
	Manifest                      map[string]any `plist:"Manifest,omitempty"`
	MobileDeviceMinVersion        string         `plist:"MobileDeviceMinVersion,omitempty"`
	MultitouchFirmwareProject     string         `plist:"MultitouchFirmwareProject,omitempty"`
	NumTimers                     string         `plist:"NumTimers,omitempty"`
	OSRamdiskSupport              bool           `plist:"OSRamdiskSupport,omitempty"`
	PMPFirmwareType               string         `plist:"PMPFirmwareType,omitempty"`
	PearlCertificationRootPub     []byte         `plist:"PearlCertificationRootPub,omitempty"`
	Platform                      string         `plist:"Platform,omitempty"`
	PlatformGeneration            string         `plist:"PlatformGeneration,omitempty"`
	PlatformName                  string         `plist:"PlatformName,omitempty"`
	ProductDescription            string         `plist:"ProductDescription,omitempty"`
	ProductID                     string         `plist:"ProductID,omitempty"`
	ProductName                   string         `plist:"ProductName,omitempty"`
	ProductNameOverride           string         `plist:"ProductNameOverride,omitempty"`
	ProductType                   string         `plist:"ProductType,omitempty"`
	RapBoardID                    string         `plist:"Rap,BoardID,omitempty"`
	RapChipID                     string         `plist:"Rap,ChipID,omitempty"`
	RapSecurityDomain             string         `plist:"Rap,SecurityDomain,omitempty"`
	RequiresAudioCodecFirmware    bool           `plist:"RequiresAudioCodecFirmware,omitempty"`
	RequiresUIDMode               bool           `plist:"RequiresUIDMode,omitempty"`
	ResearchSupported             bool           `plist:"ResearchSupported,omitempty"`
	RoseTarget                    string         `plist:"RoseTarget,omitempty"`
	SDKPlatform                   string         `plist:"SDKPlatform,omitempty"`
	SEChipID                      string         `plist:"SE,ChipID,omitempty"`
	SEPPKASupport                 bool           `plist:"SEPPKASupport,omitempty"`
	SEPSiKASupport                bool           `plist:"SEPSiKASupport,omitempty"`
	SandmanSupport                bool           `plist:"SandmanSupport,omitempty"`
	SavageChipID                  string         `plist:"Savage,ChipID,omitempty"`
	SavagePatchEpoch              string         `plist:"Savage,PatchEpoch,omitempty"`
	SecurityDomain                string         `plist:"SecurityDomain,omitempty"`
	SecurityEpoch                 string         `plist:"SecurityEpoch,omitempty"`
	SingleStageBoot               bool           `plist:"SingleStageBoot,omitempty"`
	TicketPrefix                  string         `plist:"TicketPrefix,omitempty"`
	StorageType                   string         `plist:"StorageType,omitempty"`
	SyscfgFDRDataClasses          string         `plist:"SyscfgFDRDataClasses,omitempty"`
	VeridianTarget                string         `plist:"VeridianTarget,omitempty"`
	WirelessPowerFirmwareType     string         `plist:"WirelessPowerFirmwareType,omitempty"`
	EUICCChipID                   string         `plist:"eUICC,ChipID,omitempty"`
	IBootType                     string         `plist:"iBootType,omitempty"`
}

func ParseDeviceMap(data []byte) (*DeviceMap, error) {
	dm := &DeviceMap{}
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(dm); err != nil {
		return nil, fmt.Errorf("failed to decode device map: %w", err)
	}
	return dm, nil
}

func (dm DeviceMap) String() string {
	var out string
	for boardconfig, device := range dm {
		out += fmt.Sprintf("%s, board_config: %s\n", device, boardconfig)
	}
	return out
}

func (d Device) String() string {
	name := d.ProductName
	if len(d.ProductDescription) > len(d.ProductName) {
		name = d.ProductDescription
	}
	return fmt.Sprintf("id: %s, prod_name: %s, plat: %s, cp_id: %s, board_id: %s arch: %s, sdk: %s",
		d.ProductType,
		name,
		d.Platform,
		d.ChipID,
		d.BoardID,
		d.KernelMachOArchitecture,
		d.SDKPlatform,
	)
}
