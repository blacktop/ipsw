package plist

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/ota/types"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
)

// Plists IPSW/OTA plists object
type Plists struct {
	Type           string `json:"type,omitempty"`
	*BuildManifest `json:"build_manifest,omitempty"`
	*Restore       `json:"restore,omitempty"`
	*AssetDataInfo `json:"asset_data_info,omitempty"`
	*OTAInfo       `json:"ota_info,omitempty"`
	*SystemVersion `json:"system_version,omitempty"`
}

// AssetDataInfo AssetData/Info.plist object found in OTAs
type AssetDataInfo struct {
	ActualMinimumSystemPartition int               `plist:"ActualMinimumSystemPartition,omitempty" json:"actual_minimum_system_partition,omitempty"`
	Build                        string            `plist:"Build,omitempty" json:"build,omitempty"`
	DeviceClass                  string            `plist:"DeviceClass,omitempty" json:"device_class,omitempty"`
	HardwareModel                string            `plist:"HardwareModel,omitempty" json:"hardware_model,omitempty"`
	MinimumSystemPartition       int               `plist:"MinimumSystemPartition,omitempty" json:"minimum_system_partition,omitempty"`
	PackageVersion               string            `plist:"PackageVersion,omitempty" json:"package_version,omitempty"`
	ProductType                  string            `plist:"ProductType,omitempty" json:"product_type,omitempty"`
	ProductVersion               string            `plist:"ProductVersion,omitempty" json:"product_version,omitempty"`
	RSEPDigest                   []byte            `plist:"RSEPDigest,omitempty" json:"rsep_digest,omitempty"`
	RSEPTBMDigests               []byte            `plist:"RSEPTBMDigests,omitempty" json:"rseptbm_digests,omitempty"`
	RequiredSpace                int               `plist:"RequiredSpace,omitempty" json:"required_space,omitempty"`
	ReserveFileAware             bool              `plist:"ReserveFileAware,omitempty" json:"reserve_file_aware,omitempty"`
	SEPDigest                    []byte            `plist:"SEPDigest,omitempty" json:"sep_digest,omitempty"`
	SEPTBMDigests                []byte            `plist:"SEPTBMDigests,omitempty" json:"septbm_digests,omitempty"`
	SizeArchiveRoot              int               `plist:"SizeArchiveRoot,omitempty" json:"size_archive_root,omitempty"`
	SizePatchedBinaries          int               `plist:"SizePatchedBinaries,omitempty" json:"size_patched_binaries,omitempty"`
	SizePatchedBinariesSnapshot  int               `plist:"SizePatchedBinaries-Snapshot,omitempty" json:"size_patched_binaries_snapshot,omitempty"`
	SystemPartitionPadding       map[string]int    `plist:"SystemPartitionPadding,omitempty" json:"system_partition_padding,omitempty"`
	SystemUpdatePathMap          map[string]string `plist:"SystemUpdatePathMap,omitempty" json:"system_update_path_map,omitempty"`
	SystemVolumeSealingOverhead  int               `plist:"SystemVolumeSealingOverhead,omitempty" json:"system_volume_sealing_overhead,omitempty"`
	TargetUpdate                 string            `plist:"TargetUpdate,omitempty" json:"target_update,omitempty"`
}

// AssetDataInfo Stringer
func (a *AssetDataInfo) String() string {
	var out string
	out += "[AssetData/Info.plist]\n"
	out += "======================\n"
	out += fmt.Sprintf("Build:                        %s\n", a.Build)
	out += fmt.Sprintf("DeviceClass:                  %s\n", a.DeviceClass)
	out += fmt.Sprintf("HardwareModel:                %s\n", a.HardwareModel)
	out += fmt.Sprintf("MinimumSystemPartition:       %d\n", a.MinimumSystemPartition)
	out += fmt.Sprintf("PackageVersion:               %s\n", a.PackageVersion)
	out += fmt.Sprintf("ProductType:                  %s\n", a.ProductType)
	out += fmt.Sprintf("ProductVersion:               %s\n", a.ProductVersion)
	out += fmt.Sprintf("RequiredSpace:                %s\n", humanize.Bytes(uint64(a.RequiredSpace)))
	out += fmt.Sprintf("ReserveFileAware:             %v\n", a.ReserveFileAware)
	out += fmt.Sprintf("SizeArchiveRoot:              %s\n", humanize.Bytes(uint64(a.SizeArchiveRoot)))
	out += fmt.Sprintf("SizePatchedBinaries:          %s\n", humanize.Bytes(uint64(a.SizePatchedBinaries)))
	out += fmt.Sprintf("SizePatchedBinaries-Snapshot: %s\n", humanize.Bytes(uint64(a.SizePatchedBinariesSnapshot)))
	if len(a.SystemUpdatePathMap) > 0 {
		out += "SystemUpdatePathMap:\n"
		for k, v := range a.SystemUpdatePathMap {
			out += fmt.Sprintf("  - %s: %s\n", k, v)
		}
	}
	out += fmt.Sprintf("SystemVolumeSealingOverhead:  %d\n", a.SystemVolumeSealingOverhead)
	out += fmt.Sprintf("TargetUpdate:                 %s\n", a.TargetUpdate)
	return out
}

// OTAInfo Info.plist object found in OTAs
type OTAInfo struct {
	CFBundleIdentifier            string      `plist:"CFBundleIdentifier,omitempty" json:"cf_bundle_identifier,omitempty"`
	CFBundleInfoDictionaryVersion string      `plist:"CFBundleInfoDictionaryVersion,omitempty" json:"cf_bundle_info_dictionary_version,omitempty"`
	CFBundleName                  string      `plist:"CFBundleName,omitempty" json:"cf_bundle_name,omitempty"`
	CFBundleShortVersionString    string      `plist:"CFBundleShortVersionString,omitempty" json:"cf_bundle_short_version_string,omitempty"`
	CFBundleVersion               string      `plist:"CFBundleVersion,omitempty" json:"cf_bundle_version,omitempty"`
	MobileAssetProperties         types.Asset `plist:"MobileAssetProperties,omitempty" json:"mobile_asset_properties"`
}

// OTAInfo Stringer
func (o *OTAInfo) String() string {
	var out string
	out += "[OTA Info.plist]\n"
	out += "================\n"
	out += fmt.Sprintf("CFBundleIdentifier:            %s\n", o.CFBundleIdentifier)
	// out += fmt.Sprintf("CFBundleInfoDictionaryVersion: %s\n", o.CFBundleInfoDictionaryVersion)
	// out += fmt.Sprintf("CFBundleName:                  %s\n", o.CFBundleName)
	// out += fmt.Sprintf("CFBundleShortVersionString:    %s\n", o.CFBundleShortVersionString)
	// out += fmt.Sprintf("CFBundleVersion:               %s\n", o.CFBundleVersion)
	out += fmt.Sprintf("MobileAssetProperties:\n  %s\n", o.MobileAssetProperties)
	return out
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
		return nil, fmt.Errorf("failed to open IPSW zip: %s", err)
	}
	defer zr.Close()

	return ParseZipFiles(zr.File)
}

// ParseZipFiles parses plists in remote ipsw zip
func ParseZipFiles(files []*zip.File) (*Plists, error) {
	ipsw := &Plists{Type: "IPSW"}

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
				ipsw.Type = "OTA"
				dat, err := readZipFile(f)
				if err != nil {
					return nil, fmt.Errorf("failed to read plist file: %s", err)
				}
				ipsw.AssetDataInfo, err = ParseAssetDataInfoPlist(dat)
				if err != nil {
					return nil, err
				}
			case strings.EqualFold(f.Name, "Info.plist"):
				ipsw.Type = "OTA"
				dat, err := readZipFile(f)
				if err != nil {
					return nil, fmt.Errorf("failed to read plist file: %s", err)
				}
				ipsw.OTAInfo, err = ParseOTAInfo(dat)
				if err != nil {
					return nil, err
				}
			case strings.HasSuffix(f.Name, "SystemVersion.plist"):
				dat, err := readZipFile(f)
				if err != nil {
					return nil, fmt.Errorf("failed to read plist file: %s", err)
				}
				ipsw.SystemVersion, err = ParseSystemVersion(dat)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return ipsw, nil
}

func ParsePlistFiles(files []fs.File) (*Plists, error) {
	ipsw := &Plists{Type: "IPSW"}

	for _, f := range files {
		fi, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("failed to get file info: %s", err)
		}
		switch {
		case strings.HasSuffix(fi.Name(), "Restore.plist"):
			dat, err := io.ReadAll(f)
			if err != nil {
				return nil, fmt.Errorf("failed to read plist file: %s", err)
			}
			ipsw.Restore, err = ParseRestore(dat)
			if err != nil {
				return nil, err
			}
		case strings.HasSuffix(fi.Name(), "BuildManifest.plist"):
			if strings.Contains(fi.Name(), "Restore") {
				continue
			}
			dat, err := io.ReadAll(f)
			if err != nil {
				return nil, fmt.Errorf("failed to read plist file: %s", err)
			}
			ipsw.BuildManifest, err = ParseBuildManifest(dat)
			if err != nil {
				return nil, err
			}
		case strings.HasSuffix(fi.Name(), "AssetData/Info.plist"):
			ipsw.Type = "OTA"
			dat, err := io.ReadAll(f)
			if err != nil {
				return nil, fmt.Errorf("failed to read plist file: %s", err)
			}
			ipsw.AssetDataInfo, err = ParseAssetDataInfoPlist(dat)
			if err != nil {
				return nil, err
			}
		case strings.EqualFold(fi.Name(), "Info.plist"):
			ipsw.Type = "OTA"
			dat, err := io.ReadAll(f)
			if err != nil {
				return nil, fmt.Errorf("failed to read plist file: %s", err)
			}
			ipsw.OTAInfo, err = ParseOTAInfo(dat)
			if err != nil {
				return nil, err
			}
		case strings.HasSuffix(fi.Name(), "SystemVersion.plist"):
			dat, err := io.ReadAll(f)
			if err != nil {
				return nil, fmt.Errorf("failed to read plist file: %s", err)
			}
			ipsw.SystemVersion, err = ParseSystemVersion(dat)
			if err != nil {
				return nil, err
			}
		}
	}

	return ipsw, nil
}

func (p *Plists) GetOSType() string {
	if p != nil && p.OTAInfo != nil {
		if len(p.OTAInfo.MobileAssetProperties.ReleaseType) > 0 {
			return p.OTAInfo.MobileAssetProperties.ReleaseType
		} else {
			return p.OTAInfo.MobileAssetProperties.DocumentationID
		}
	} else if os, ok := p.BuildManifest.BuildIdentities[0].Info.VariantContents["OS"]; ok {
		return os
	}
	return "?"
}

func (p *Plists) GetKernelType(name string) string {
	for _, bID := range p.BuildManifest.BuildIdentities {
		if strings.EqualFold(bID.Manifest["KernelCache"].Info["Path"].(string), name) {
			return bID.Info.VariantContents["InstalledKernelCache"]
		}
	}
	return p.OTAInfo.MobileAssetProperties.ReleaseType
}

func (p *Plists) GetDeviceForBoardConfig(boardConfig string) *restoreDeviceMap {
	if p != nil && p.Restore != nil {
		for _, dmap := range p.Restore.DeviceMap {
			if strings.EqualFold(dmap.BoardConfig, boardConfig) {
				return &dmap
			}
		}
	}
	return nil
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
