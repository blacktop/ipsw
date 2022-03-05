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
	"github.com/blacktop/ipsw/pkg/ota/types"
	"github.com/pkg/errors"
)

// Plists IPSW/OTA plists object
type Plists struct {
	*BuildManifest
	*Restore
	*AssetDataInfo
	*OTAInfo
}

// AssetDataInfo AssetData/Info.plist object found in OTAs
type AssetDataInfo struct {
	ActualMinimumSystemPartition int               `plist:"ActualMinimumSystemPartition,omitempty"`
	Build                        string            `plist:"Build,omitempty"`
	DeviceClass                  string            `plist:"DeviceClass,omitempty"`
	HardwareModel                string            `plist:"HardwareModel,omitempty"`
	MinimumSystemPartition       int               `plist:"MinimumSystemPartition,omitempty"`
	PackageVersion               string            `plist:"PackageVersion,omitempty"`
	ProductType                  string            `plist:"ProductType,omitempty"`
	ProductVersion               string            `plist:"ProductVersion,omitempty"`
	RSEPDigest                   []byte            `plist:"RSEPDigest,omitempty"`
	RSEPTBMDigests               []byte            `plist:"RSEPTBMDigests,omitempty"`
	RequiredSpace                int               `plist:"RequiredSpace,omitempty"`
	ReserveFileAware             bool              `plist:"ReserveFileAware,omitempty"`
	SEPDigest                    []byte            `plist:"SEPDigest,omitempty"`
	SEPTBMDigests                []byte            `plist:"SEPTBMDigests,omitempty"`
	SizeArchiveRoot              int               `plist:"SizeArchiveRoot,omitempty"`
	SizePatchedBinaries          int               `plist:"SizePatchedBinaries,omitempty"`
	SizePatchedBinariesSnapshot  int               `plist:"SizePatchedBinaries-Snapshot,omitempty"`
	SystemPartitionPadding       map[string]int    `plist:"SystemPartitionPadding,omitempty"`
	SystemUpdatePathMap          map[string]string `plist:"SystemUpdatePathMap,omitempty"`
	SystemVolumeSealingOverhead  int               `plist:"SystemVolumeSealingOverhead,omitempty"`
	TargetUpdate                 string            `plist:"TargetUpdate,omitempty"`
}

// OTAInfo Info.plist object found in OTAs
type OTAInfo struct {
	CFBundleIdentifier            string      `plist:"CFBundleIdentifier,omitempty"`
	CFBundleInfoDictionaryVersion string      `plist:"CFBundleInfoDictionaryVersion,omitempty"`
	CFBundleName                  string      `plist:"CFBundleName,omitempty"`
	CFBundleShortVersionString    string      `plist:"CFBundleShortVersionString,omitempty"`
	CFBundleVersion               string      `plist:"CFBundleVersion,omitempty"`
	MobileAssetProperties         types.Asset `plist:"MobileAssetProperties,omitempty"`
}

func readZipFile(f *zip.File) ([]byte, error) {
	pData := make([]byte, f.UncompressedSize64)
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open file within zip: %s", err)
	}
	defer rc.Close()
	io.ReadFull(rc, pData)
	return pData, nil
}

// Extract extracts plists from IPSW
func Extract(ipsw string) error {
	log.Info("Extracting plists from IPSW")

	_, err := utils.Unzip(ipsw, "", func(f *zip.File) bool {
		var validPlist = regexp.MustCompile(`.*plist$`)
		return validPlist.MatchString(f.Name)
	})
	if err != nil {
		return errors.Wrap(err, "failed to extract plists from ipsw")
	}

	return nil
}

// ParseOTAInfo parses the Info.plist file from an OTA
func ParseOTAInfo(data []byte) (*OTAInfo, error) {
	i := &OTAInfo{}
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(i); err != nil {
		return nil, fmt.Errorf("failed to decode OTA Info.plist: %w", err)
	}
	return i, nil
}

// ParseBuildManifest parses the AssetData/Info.plist file from an OTA
func ParseAssetDataInfoPlist(data []byte) (*AssetDataInfo, error) {
	i := &AssetDataInfo{}
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(i); err != nil {
		return nil, fmt.Errorf("failed to parse AssetData/Info.plist: %w", err)
	}
	return i, nil
}

// Parse parses plist files in a local IPSW/OTA file
func Parse(path string) (*Plists, error) {

	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open ipsw zip: %s", err)
	}
	defer zr.Close()

	return ParseZipFiles(zr.File)
}

// ParseZipFiles parses plists in remote ipsw zip
func ParseZipFiles(files []*zip.File) (*Plists, error) {
	ipsw := &Plists{}

	for _, f := range files {
		if regexp.MustCompile(`.*plist$`).MatchString(f.Name) {
			switch {
			case strings.HasSuffix(f.Name, "Restore.plist"):
				dat, err := readZipFile(f)
				if err != nil {
					return nil, fmt.Errorf("failed to read plist file: %s", err)
				}
				ipsw.Restore, err = ParseRestore(dat)
				if err != nil {
					return nil, err
				}
			case strings.HasSuffix(f.Name, "BuildManifest.plist"):
				if strings.Contains(f.Name, "Restore") {
					continue
				}
				dat, err := readZipFile(f)
				if err != nil {
					return nil, fmt.Errorf("failed to read plist file: %s", err)
				}
				ipsw.BuildManifest, err = ParseBuildManifest(dat)
				if err != nil {
					return nil, err
				}
			case strings.HasSuffix(f.Name, "AssetData/Info.plist"):
				dat, err := readZipFile(f)
				if err != nil {
					return nil, fmt.Errorf("failed to read plist file: %s", err)
				}
				ipsw.AssetDataInfo, err = ParseAssetDataInfoPlist(dat)
				if err != nil {
					return nil, err
				}
			case strings.EqualFold(f.Name, "Info.plist"):
				dat, err := readZipFile(f)
				if err != nil {
					return nil, fmt.Errorf("failed to read plist file: %s", err)
				}
				ipsw.OTAInfo, err = ParseOTAInfo(dat)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return ipsw, nil
}

func (p *Plists) GetOSType() string {
	if len(p.BuildManifest.BuildIdentities[0].Info.VariantContents["OS"]) > 0 {
		return p.BuildManifest.BuildIdentities[0].Info.VariantContents["OS"]
	}
	if p.OTAInfo != nil {
		return p.OTAInfo.MobileAssetProperties.ReleaseType
	}
	return ""
}

func (p *Plists) GetKernelType(name string) string {
	for _, bID := range p.BuildManifest.BuildIdentities {
		if strings.EqualFold(bID.Manifest["KernelCache"].Info.Path, name) {
			return bID.Info.VariantContents["InstalledKernelCache"]
		}
	}
	return p.OTAInfo.MobileAssetProperties.ReleaseType
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
	iStr += "FileSystem     = "
	for file, fsType := range i.Restore.SystemRestoreImageFileSystems {
		iStr += fmt.Sprintf("%s (Type: %s)\n", file, fsType)
	}
	iStr += "\nSupported Products:\n"
	for _, prodType := range i.BuildManifest.SupportedProductTypes {
		iStr += fmt.Sprintf(" - %s\n", prodType)
	}
	iStr += "\nDeviceMap:\n"
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
	iStr += "\nKernelCaches:\n"
	kcs := i.BuildManifest.GetKernelCaches()
	for key, value := range kcs {
		iStr += fmt.Sprintf(" - BoardConfig: %s => %s\n", key, value)
	}
	return iStr
}
