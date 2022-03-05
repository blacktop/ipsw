package plist

import (
	"bytes"
	"fmt"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
)

// BuildManifest is the BuildManifest.plist object found in IPSWs/OTAs
type BuildManifest struct {
	BuildIdentities       []buildIdentity `plist:"BuildIdentities,omitempty"`
	ManifestVersion       uint64          `plist:"ManifestVersion,omitempty"`
	ProductBuildVersion   string          `plist:"ProductBuildVersion,omitempty"`
	ProductVersion        string          `plist:"ProductVersion,omitempty"`
	SupportedProductTypes []string        `plist:"SupportedProductTypes,omitempty"`
}

type buildIdentity struct {
	ApBoardID                     string
	ApChipID                      string
	ApSecurityDomain              string
	BbActivationManifestKeyHash   []byte
	BbChipID                      string
	BbFDRSecurityKeyHash          []byte
	BbProvisioningManifestKeyHash []byte
	Info                          buildIdentityInfo
	Manifest                      map[string]buildIdentityManifest
	PearlCertificationRootPub     []byte
	ProductMarketingVersion       string
	SEChipID                      string `plist:"SE,ChipID,omitempty"`
	SavageChipID                  string `plist:"Savage,ChipID,omitempty"`
	SavagePatchEpoch              string `plist:"Savage,PatchEpoch,omitempty"`
	UniqueBuildID                 []byte
	YonkersBoardID                int    `plist:"Yonkers,BoardID,omitempty"`
	YonkersChipID                 string `plist:"Yonkers,ChipID,omitempty"`
	YonkersPatchEpoch             int    `plist:"Yonkers,PatchEpoch,omitempty"`
	RapBoardID                    int    `plist:"Rap,BoardID,omitempty"`
	RapChipID                     int    `plist:"Rap,ChipID,omitempty"`
	RapSecurityDomain             int    `plist:"Rap,SecurityDomain,omitempty"`
	EUICCChipID                   int    `plist:"eUICC,ChipID,omitempty"`
}

type buildIdentityInfo struct {
	BuildNumber            string
	CodeName               string `plist:"BuildTrain,omitempty"`
	DeviceClass            string
	FDRSupport             bool
	MinimumSystemPartition int
	MobileDeviceMinVersion string
	OSVarContentSize       int
	RestoreBehavior        string
	SystemPartitionPadding map[string]int
	Variant                string
	VariantContents        map[string]string
}

type buildIdentityManifest struct {
	Digest      []byte
	BuildString string `plist:"BuildString,omitempty"`
	Info        buildIdentityManifestInfo
	Trusted     bool
}

type buildIdentityManifestInfo struct {
	IsFTAB                      bool
	IsFUDFirmware               bool `plist:"IsFUDFirmware,omitempty"`
	IsFirmwarePayload           bool `plist:"IsFirmwarePayload,omitempty"`
	IsLoadedByiBoot             bool
	IsLoadedByiBootStage1       bool
	IsiBootEANFirmware          bool
	IsiBootNonEssentialFirmware bool
	Path                        string `plist:"Path"`
	Personalize                 bool
	RestoreRequestRules         []interface{}
}

// ParseBuildManifest parses the BuildManifest.plist
func ParseBuildManifest(data []byte) (*BuildManifest, error) {
	bm := &BuildManifest{}
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(bm); err != nil {
		return nil, fmt.Errorf("failed to decode BuildManifest.plist: %w", err)
	}
	return bm, nil
}

func (b *BuildManifest) GetKernelCaches() map[string][]string {
	kernelCaches := make(map[string][]string, len(b.BuildIdentities))
	for _, bID := range b.BuildIdentities {
		if !utils.StrSliceHas(kernelCaches[bID.Info.DeviceClass], bID.Manifest["KernelCache"].Info.Path) {
			kernelCaches[bID.Info.DeviceClass] = append(kernelCaches[bID.Info.DeviceClass], bID.Manifest["KernelCache"].Info.Path)
		}
	}
	return kernelCaches
}

func (b *BuildManifest) GetBootLoaders() map[string][]string {
	bootLoaders := make(map[string][]string, len(b.BuildIdentities))
	for _, bID := range b.BuildIdentities {
		if !utils.StrSliceHas(bootLoaders[bID.Info.DeviceClass], bID.Manifest["iBEC"].Info.Path) {
			if len(bID.Manifest["iBEC"].Info.Path) > 0 {
				bootLoaders[bID.Info.DeviceClass] = append(bootLoaders[bID.Info.DeviceClass], bID.Manifest["iBEC"].Info.Path)
			}
		}
		if !utils.StrSliceHas(bootLoaders[bID.Info.DeviceClass], bID.Manifest["iBoot"].Info.Path) {
			if len(bID.Manifest["iBoot"].Info.Path) > 0 {
				bootLoaders[bID.Info.DeviceClass] = append(bootLoaders[bID.Info.DeviceClass], bID.Manifest["iBoot"].Info.Path)
			}
		}
		if !utils.StrSliceHas(bootLoaders[bID.Info.DeviceClass], bID.Manifest["iBSS"].Info.Path) {
			if len(bID.Manifest["iBSS"].Info.Path) > 0 {
				bootLoaders[bID.Info.DeviceClass] = append(bootLoaders[bID.Info.DeviceClass], bID.Manifest["iBSS"].Info.Path)
			}
		}
		if !utils.StrSliceHas(bootLoaders[bID.Info.DeviceClass], bID.Manifest["LLB"].Info.Path) {
			if len(bID.Manifest["LLB"].Info.Path) > 0 {
				bootLoaders[bID.Info.DeviceClass] = append(bootLoaders[bID.Info.DeviceClass], bID.Manifest["LLB"].Info.Path)
			}
		}
	}
	return bootLoaders
}
