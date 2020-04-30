package plist

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
)

// Plists ipsw plists object
type Plists struct {
	*BuildManifest
	*Restore
	*OTAInfo
	*Info
}

type BuildManifest struct {
	BuildIdentities       []buildIdentity `plist:"BuildIdentities,omitempty"`
	ManifestVersion       uint64          `plist:"ManifestVersion,omitempty"`
	ProductBuildVersion   string          `plist:"ProductBuildVersion,omitempty"`
	ProductVersion        string          `plist:"ProductVersion,omitempty"`
	SupportedProductTypes []string        `plist:"SupportedProductTypes,omitempty"`
}

type buildIdentity struct {
	ApBoardID               string
	ApChipID                string
	ApSecurityDomain        string
	BbChipID                string
	Info                    buildIdentityInfo
	Manifest                map[string]buildIdentityManifestType
	ProductMarketingVersion string
}

type buildIdentityInfo struct {
	BuildNumber            string
	BuildTrain             string
	DeviceClass            string
	FDRSupport             bool
	MinimumSystemPartition int
	MobileDeviceMinVersion string
	OSVarContentSize       int
	RestoreBehavior        string
	Variant                string
	VariantContents        variantContents
}

type variantContents struct {
	BasebandFirmware     string
	DFU                  string
	Firmware             string
	InstalledKernelCache string
	OS                   string
	RestoreKernelCache   string
	RestoreRamDisk       string
	RestoreSEP           string
	SEP                  string
	VinylFirmware        string
}

type buildIdentityManifestType struct {
	Digest  []byte
	Info    buildIdentityManifestInfo
	Trusted bool
}
type buildIdentityManifestInfo struct {
	IsFTAB            bool
	IsFUDFirmware     bool `plist:"IsFUDFirmware,omitempty"`
	IsFirmwarePayload bool `plist:"IsFirmwarePayload,omitempty"`
	IsLoadedByiBoot   bool
	Path              string `plist:"Path"`
	Personalize       bool
}

type OTAInfo struct {
	CFBundleIdentifier    string                `plist:"CFBundleIdentifier,omitempty"`
	MobileAssetProperties mobileAssetProperties `plist:"MobileAssetProperties,omitempty"`
}

type mobileAssetProperties struct {
	Build                 string   `plist:"Build,omitempty"`
	OSVersion             string   `plist:"OSVersion,omitempty"`
	ReleaseType           string   `plist:"ReleaseType,omitempty"`
	SupportedDeviceModels []string `plist:"SupportedDeviceModels,omitempty"`
	SupportedDevices      []string `plist:"SupportedDevices,omitempty"`
}

// Info object found in OTAs
type Info struct {
	DeviceClass    string `plist:"DeviceClass,omitempty"`
	HardwareModel  string `plist:"HardwareModel,omitempty"`
	PackageVersion string `plist:"PackageVersion,omitempty"`
	ProductType    string `plist:"ProductType,omitempty"`
	ProductVersion string `plist:"ProductVersion,omitempty"`
	Build          string `plist:"TargetUpdate,omitempty"`
}

type Restore struct {
	DeviceMap                     []restoreDeviceMap `plist:"DeviceMap,omitempty"`
	ProductBuildVersion           string             `plist:"ProductBuildVersion,omitempty"`
	ProductVersion                string             `plist:"ProductVersion,omitempty"`
	SupportedProductTypeIDs       map[string][]int   `plist:"SupportedProductTypeIDs,omitempty"`
	SupportedProductTypes         []string           `plist:"SupportedProductTypes,omitempty"`
	SystemRestoreImageFileSystems map[string]string  `plist:"SystemRestoreImageFileSystems,omitempty"`
}

type restoreDeviceMap struct {
	BDID        int
	BoardConfig string
	CPID        int
	Platform    string
	SCEP        int
	SDOM        int
}

func (p *Plists) GetOSType() string {
	if len(p.BuildManifest.BuildIdentities[0].Info.VariantContents.OS) > 0 {
		return p.BuildManifest.BuildIdentities[0].Info.VariantContents.OS
	}
	return p.OTAInfo.MobileAssetProperties.ReleaseType
}

func (b *BuildManifest) GetKernelCaches() map[string]string {
	kernelCaches := make(map[string]string, len(b.BuildIdentities))
	for _, bID := range b.BuildIdentities {
		kernelCaches[bID.Info.DeviceClass] = bID.Manifest["KernelCache"].Info.Path
	}
	return kernelCaches
}

func (i *Plists) String() string {
	var iStr string
	iStr += fmt.Sprintf(
		"[Plists Info]\n"+
			"===========\n"+
			"Version        = %s\n"+
			"BuildVersion   = %s\n"+
			"OS Type        = %s\n",
		i.BuildManifest.ProductVersion,
		i.BuildManifest.ProductBuildVersion,
		i.GetOSType(),
	)
	iStr += fmt.Sprintf("FileSystem     = ")
	for file, fsType := range i.Restore.SystemRestoreImageFileSystems {
		iStr += fmt.Sprintf("%s (Type: %s)\n", file, fsType)
	}
	iStr += fmt.Sprintf("\nSupported Products:\n")
	for _, prodType := range i.BuildManifest.SupportedProductTypes {
		iStr += fmt.Sprintf(" - %s\n", prodType)
	}
	iStr += fmt.Sprintf("\nDeviceMap:\n")
	for _, device := range i.Restore.DeviceMap {
		iStr += fmt.Sprintf(
			"BDID %d)\n"+
				"  - BoardConfig = %s\n"+
				"  - CPID        = %d\n"+
				"  - Platform    = %s\n"+
				"  - SCEP        = %d\n"+
				"  - SDOM        = %d\n",
			device.BDID,
			device.BoardConfig,
			device.CPID,
			device.Platform,
			device.SCEP,
			device.SDOM,
		)
	}
	iStr += fmt.Sprintf("\nKernelCaches:\n")
	kcs := i.BuildManifest.GetKernelCaches()
	for key, value := range kcs {
		iStr += fmt.Sprintf(" - BoardConfig: %s => %s\n", key, value)
	}
	return iStr
}

// parseBuildManifest parses the BuildManifest.plist
func parseBuildManifest(data []byte) (*BuildManifest, error) {
	bm := &BuildManifest{}

	decoder := plist.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(bm)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse BuildManifest.plist")
	}

	return bm, nil
}

// parseRestore parses the Restore.plist
func parseRestore(data []byte) (*Restore, error) {
	r := &Restore{}

	decoder := plist.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse Restore.plist")
	}

	return r, nil
}

func parseOTAInfo(data []byte) (*OTAInfo, error) {
	o := &OTAInfo{}

	decoder := plist.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(o)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse Info.plist")
	}

	return o, nil
}

func parseInfoPlist(data []byte) (*Info, error) {
	i := &Info{}

	decoder := plist.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(i)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse AssetData/Info.plist")
	}

	return i, nil
}

// Parse parses plist files in a local ipsw file
func Parse(ipswPath string) (*Plists, error) {

	zr, err := zip.OpenReader(ipswPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open ipsw as zip")
	}
	defer zr.Close()

	return ParseZipFiles(zr.File)
}

// ParseZipFiles parses plists in remote ipsw zip
func ParseZipFiles(files []*zip.File) (*Plists, error) {
	ipsw := &Plists{}

	var validPlist = regexp.MustCompile(`.*plist$`)

	for _, f := range files {
		if validPlist.MatchString(f.Name) {
			switch {
			case strings.HasSuffix(f.Name, "Restore.plist"):
				pData := make([]byte, f.UncompressedSize64)
				rc, err := f.Open()
				if err != nil {
					return nil, errors.Wrapf(err, "failed to open file in zip: %s", f.Name)
				}
				io.ReadFull(rc, pData)
				rc.Close()
				ipsw.Restore, err = parseRestore(pData)
				if err != nil {
					return nil, errors.Wrap(err, "failed to parse DeviceTree")
				}
			case strings.HasSuffix(f.Name, "BuildManifest.plist"):
				pData := make([]byte, f.UncompressedSize64)
				rc, err := f.Open()
				if err != nil {
					return nil, errors.Wrapf(err, "failed to open file in zip: %s", f.Name)
				}
				io.ReadFull(rc, pData)
				rc.Close()
				ipsw.BuildManifest, err = parseBuildManifest(pData)
				if err != nil {
					return nil, errors.Wrap(err, "failed to parse DeviceTree")
				}
			case strings.HasSuffix(f.Name, "AssetData/Info.plist"):
				pData := make([]byte, f.UncompressedSize64)
				rc, err := f.Open()
				if err != nil {
					return nil, errors.Wrapf(err, "failed to open file in zip: %s", f.Name)
				}
				io.ReadFull(rc, pData)
				rc.Close()
				ipsw.Info, err = parseInfoPlist(pData)
				if err != nil {
					return nil, errors.Wrap(err, "failed to parse DeviceTree")
				}
			case strings.EqualFold(f.Name, "Info.plist"):
				pData := make([]byte, f.UncompressedSize64)
				rc, err := f.Open()
				if err != nil {
					return nil, errors.Wrapf(err, "failed to open file in zip: %s", f.Name)
				}
				io.ReadFull(rc, pData)
				rc.Close()
				ipsw.OTAInfo, err = parseOTAInfo(pData)
				if err != nil {
					return nil, errors.Wrap(err, "failed to parse DeviceTree")
				}
			default:
				log.Debugf("found unsupported plist %s", f.Name)
			}
		}
	}
	return ipsw, nil
}

// Extract extracts plists from ipsw
func Extract(ipsw string) error {
	log.Info("Extracting plists from IPSW")
	_, err := utils.Unzip(ipsw, "", func(f *zip.File) bool {
		var validPlist = regexp.MustCompile(`.*plist$`)
		if validPlist.MatchString(f.Name) {
			return true
		}
		return false
	})

	if err != nil {
		return errors.Wrap(err, "failed to extract plists from ipsw")
	}

	return nil
}
