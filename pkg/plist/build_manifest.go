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
	ManifestVersion       int             `plist:"ManifestVersion,omitempty"`
	ProductBuildVersion   string          `plist:"ProductBuildVersion,omitempty"`
	ProductVersion        string          `plist:"ProductVersion,omitempty"`
	SupportedProductTypes []string        `plist:"SupportedProductTypes,omitempty"`
}

func (b *BuildManifest) String() string {
	var out string
	out += "[BuildManifest]\n"
	out += "===============\n"
	out += fmt.Sprintf("  ManifestVersion:       %d\n", b.ManifestVersion)
	out += fmt.Sprintf("  ProductBuildVersion:   %s\n", b.ProductBuildVersion)
	out += fmt.Sprintf("  ProductVersion:        %s\n", b.ProductVersion)
	out += fmt.Sprintf("  SupportedProductTypes: %v\n", b.SupportedProductTypes)
	out += "  BuildIdentities:\n"
	for _, bID := range b.BuildIdentities {
		out += fmt.Sprintf("   -\n%s", bID.String())
	}
	return out
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
	UniqueBuildID                 []byte
}

func (i buildIdentity) String() string {
	var out string
	out += fmt.Sprintf("    ProductMarketingVersion: %s\n", i.ProductMarketingVersion)
	out += fmt.Sprintf("    ApBoardID:               %s\n", i.ApBoardID)
	out += fmt.Sprintf("    ApChipID:                %s\n", i.ApChipID)
	out += fmt.Sprintf("    ApSecurityDomain:        %s\n", i.ApSecurityDomain)
	out += fmt.Sprintf("    BbChipID:                %s\n", i.BbChipID)
	out += fmt.Sprintf("    Info:\n%s", i.Info.String())
	out += "    Manifest:\n"
	for k, v := range i.Manifest {
		if len(v.Info.Path) > 0 {
			out += fmt.Sprintf("      %s: %s\n", k, v.String())
		}
	}
	return out
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

func (i buildIdentityInfo) String() string {
	return fmt.Sprintf(
		"      BuildNumber:            %s\n"+
			"      CodeName:               %s\n"+
			"      DeviceClass:            %s\n"+
			"      FDRSupport:             %t\n"+
			"      MinimumSystemPartition: %d\n"+
			"      MobileDeviceMinVersion: %s\n"+
			"      RestoreBehavior:        %s\n"+
			"      Variant:                %s\n",
		i.BuildNumber,
		i.CodeName,
		i.DeviceClass,
		i.FDRSupport,
		i.MinimumSystemPartition,
		i.MobileDeviceMinVersion,
		i.RestoreBehavior,
		i.Variant,
	)
}

type buildIdentityManifest struct {
	Digest      []byte
	BuildString string `plist:"BuildString,omitempty"`
	Info        buildIdentityManifestInfo
	Trusted     bool
}

func (m buildIdentityManifest) String() string {
	var bs string
	if len(m.BuildString) > 0 {
		bs = fmt.Sprintf(" (%s)", m.BuildString)
	}
	return fmt.Sprintf("%s%s", m.Info.Path, bs)
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

func (b *BuildManifest) GetKernelForModel(model string) []string {
	kcs := b.GetKernelCaches()
	if v, ok := kcs[model]; ok {
		return v
	} else if len(kcs) == 1 {
		for _, v := range kcs {
			return v
		}
	}
	return nil
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
		if !utils.StrSliceHas(bootLoaders[bID.Info.DeviceClass], bID.Manifest["SEP"].Info.Path) {
			if len(bID.Manifest["SEP"].Info.Path) > 0 {
				bootLoaders[bID.Info.DeviceClass] = append(bootLoaders[bID.Info.DeviceClass], bID.Manifest["SEP"].Info.Path)
			}
		}
	}
	return bootLoaders
}
