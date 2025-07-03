package plist

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
)

// BuildManifest is the BuildManifest.plist object found in IPSWs/OTAs
type BuildManifest struct {
	BuildIdentities       []BuildIdentity `plist:"BuildIdentities,omitempty" json:"build_identities,omitempty"`
	ManifestVersion       int             `plist:"ManifestVersion,omitempty" json:"manifest_version,omitempty"`
	ProductBuildVersion   string          `plist:"ProductBuildVersion,omitempty" json:"product_build_version,omitempty"`
	ProductVersion        string          `plist:"ProductVersion,omitempty" json:"product_version,omitempty"`
	SupportedProductTypes []string        `plist:"SupportedProductTypes,omitempty" json:"supported_product_types,omitempty"`
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

type BuildIdentity struct {
	ApOSLongVersion                    string                      `plist:"Ap,OSLongVersion,omitempty" json:"ap_os_long_version,omitempty"`
	ApBoardID                          string                      `plist:"ApBoardID,omitempty" json:"ap_board_id,omitempty"`
	ApChipID                           string                      `plist:"ApChipID,omitempty" json:"ap_chip_id,omitempty"`
	ApSecurityDomain                   string                      `plist:"ApSecurityDomain,omitempty" json:"ap_security_domain,omitempty"`
	ApProductType                      string                      `plist:"Ap,ProductType,omitempty" json:"ap_product_type,omitempty"`
	ApProductMarketingVersion          string                      `plist:"Ap,ProductMarketingVersion,omitempty" json:"product_marketing_version,omitempty"`
	ApSDKPlatform                      string                      `plist:"Ap,SDKPlatform,omitempty" json:"ap_sdk_platform,omitempty"`
	ApTarget                           string                      `plist:"Ap,Target,omitempty" json:"ap_target,omitempty"`
	ApTargetType                       string                      `plist:"Ap,TargetType,omitempty" json:"ap_target_type,omitempty"`
	BbActivationManifestKeyHash        []byte                      `plist:"BbActivationManifestKeyHash,omitempty" json:"bb_activation_manifest_key_hash,omitempty"`
	BbChipID                           string                      `plist:"BbChipID,omitempty" json:"bb_chip_id,omitempty"`
	BbGoldCertId                       string                      `plist:"BbGoldCertId,omitempty" json:"bb_gold_cert_id,omitempty"`
	BbSkeyId                           []byte                      `plist:"BbSkeyId,omitempty" json:"bb_skey_id,omitempty"`
	BbFDRSecurityKeyHash               []byte                      `plist:"BbFDRSecurityKeyHash,omitempty" json:"bb_fdr_security_key_hash,omitempty"`
	BbProvisioningManifestKeyHash      []byte                      `plist:"BbProvisioningManifestKeyHash,omitempty" json:"bb_provisioning_manifest_key_hash,omitempty"`
	BbCalibrationManifestKeyHash       []byte                      `plist:"BbCalibrationManifestKeyHash,omitempty" json:"bb_calibration_manifest_key_hash,omitempty"`
	BbFactoryActivationManifestKeyHash []byte                      `plist:"BbFactoryActivationManifestKeyHash,omitempty" json:"bb_factory_activation_manifest_key_hash,omitempty"`
	Info                               IdentityInfo                `plist:"Info,omitempty" json:"info"`
	Manifest                           map[string]IdentityManifest `plist:"Manifest,omitempty" json:"manifest,omitempty"`
	PearlCertificationRootPub          []byte                      `plist:"PearlCertificationRootPub,omitempty" json:"pearl_certification_root_pub,omitempty"`
	UniqueBuildID                      []byte                      `plist:"UniqueBuildID,omitempty" json:"unique_build_id,omitempty"`
	NeRDEpoch                          uint64                      `plist:"NeRDEpoch,omitempty" json:"nerd_epoch,omitempty"`
	PermitNeRDPivot                    []byte                      `plist:"PermitNeRDPivot,omitempty" json:"permit_nerd_pivot,omitempty"`
	ApSikaFuse                         uint64                      `plist:"Ap,SikaFuse,omitempty" json:"ap_sika_fuse,omitempty"`
}

func (i BuildIdentity) String() string {
	var out string
	if len(i.ApProductMarketingVersion) > 0 {
		out += fmt.Sprintf("    ProductMarketingVersion: %s\n", i.ApProductMarketingVersion)
	}
	if len(i.ApOSLongVersion) > 0 {
		out += fmt.Sprintf("    Ap,OSLongVersion:        %s\n", i.ApOSLongVersion)
	}
	out += fmt.Sprintf("    ApBoardID:               %s\n", i.ApBoardID)
	out += fmt.Sprintf("    ApBoardID:               %s\n", i.ApBoardID)
	out += fmt.Sprintf("    ApChipID:                %s\n", i.ApChipID)
	out += fmt.Sprintf("    ApSecurityDomain:        %s\n", i.ApSecurityDomain)
	out += fmt.Sprintf("    BbChipID:                %s\n", i.BbChipID)
	out += fmt.Sprintf("    Info:\n%s", i.Info.String())
	out += "    Manifest:\n"
	for k, v := range i.Manifest {
		if path, ok := v.Info["Path"]; ok {
			if len(path.(string)) > 0 {
				out += fmt.Sprintf("      %-34s%s\n", k+":", v.String())
			}
		}
	}
	return out
}

type IdentityInfo struct {
	BuildNumber            string            `json:"build_number,omitempty"`
	CodeName               string            `plist:"BuildTrain,omitempty" json:"code_name,omitempty"`
	DeviceClass            string            `json:"device_class,omitempty"`
	FDRSupport             bool              `json:"fdr_support,omitempty"`
	MinimumSystemPartition int               `json:"minimum_system_partition,omitempty"`
	MobileDeviceMinVersion string            `json:"mobile_device_min_version,omitempty"`
	OSVarContentSize       int               `json:"os_var_content_size,omitempty"`
	RestoreBehavior        string            `json:"restore_behavior,omitempty"`
	SystemPartitionPadding map[string]int    `json:"system_partition_padding,omitempty"`
	Variant                string            `json:"variant,omitempty"`
	VariantContents        map[string]string `json:"variant_contents,omitempty"`
	ApTimestamp            int               `plist:"Ap,Timestamp,omitempty" json:"ap_timestamp,omitempty"`
}

func (i IdentityInfo) String() string {
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

// "ACDB-DownloadDigest"
// "BBCFG-DownloadDigest"
// "Misc-HashTableBody"
// "Misc-HashTableHeaderDefault"
// "Misc-PartialDigest"
// "RestoreSBL1-HashTableBody"
// "RestoreSBL1-HashTableHeaderDefault"
// "RestoreSBL1-PartialDigest"
// "RestoreSBL1-Version"
// "SBL1-HashTableBody"
// "SBL1-HashTableHeaderDefault"
// "SBL1-PartialDigest"
// "SBL1-Version"

type IdentityManifest struct {
	Digest                       []byte         `plist:"Digest,omitempty" json:"digest,omitempty" mapstructure:"Digest,omitempty"`
	DigestListSize               *int           `plist:"DigestListSize,omitempty" json:"digest_list_size,omitempty" mapstructure:"DigestListSize,omitempty"`
	FabRevision                  *int           `plist:"FabRevision,omitempty" json:"fab_revision,omitempty" mapstructure:"FabRevision,omitempty"`
	Name                         *string        `plist:"Name,omitempty" json:"name,omitempty" mapstructure:"Name,omitempty"`
	BuildString                  *string        `plist:"BuildString,omitempty" json:"build_string,omitempty" mapstructure:"BuildString,omitempty"`
	Info                         map[string]any `plist:"Info,omitempty" json:"info,omitempty" mapstructure:"Info,omitempty"`
	EPRO                         *bool          `plist:"EPRO,omitempty" json:"epro,omitempty" mapstructure:"EPRO,omitempty"`
	ESEC                         *bool          `plist:"ESEC,omitempty" json:"esec,omitempty" mapstructure:"ESEC,omitempty"`
	Trusted                      *bool          `plist:"Trusted,omitempty" json:"trusted,omitempty" mapstructure:"Trusted,omitempty"`
	MemoryMap                    *[]byte        `plist:"MemoryMap,omitempty" json:"memory_map,omitempty" mapstructure:"MemoryMap,omitempty"`
	ObjectPayloadPropertyDigest  *[]byte        `plist:"ObjectPayloadPropertyDigest,omitempty" json:"object_payload_property_digest,omitempty" mapstructure:"ObjectPayloadPropertyDigest,omitempty"`
	ProductionUpdatePayloadHash  *[]byte        `plist:"ProductionUpdatePayloadHash,omitempty" json:"production_update_payload_hash,omitempty" mapstructure:"ProductionUpdatePayloadHash,omitempty"`
	DevelopmentUpdatePayloadHash *[]byte        `plist:"DevelopmentUpdatePayloadHash,omitempty" json:"development_update_payload_hash,omitempty" mapstructure:"DevelopmentUpdatePayloadHash,omitempty"`
	RawDataDigest                *[]byte        `plist:"RawDataDigest,omitempty" json:"raw_data_digest,omitempty" mapstructure:"RawDataDigest,omitempty"`
	TBMDigests                   *[]byte        `plist:"TBMDigests,omitempty" json:"tbm_digests,omitempty" mapstructure:"TBMDigests,omitempty"`
}

func (m IdentityManifest) String() string {
	var bs string
	if m.BuildString != nil && len(*m.BuildString) > 0 {
		bs = fmt.Sprintf(" (%s)", *m.BuildString)
	}
	return fmt.Sprintf("%s%s", m.Info["Path"].(string), bs)
}

type IdentityManifestInfo struct {
	IsFTAB                      bool   `json:"is_ftab,omitempty" mapstructure:"IsFTAB,omitempty"`
	IsFUDFirmware               bool   `plist:"IsFUDFirmware,omitempty" json:"is_fud_firmware,omitempty" mapstructure:"IsFUDFirmware,omitempty"`
	IsFirmwarePayload           bool   `plist:"IsFirmwarePayload,omitempty" json:"is_firmware_payload,omitempty" mapstructure:"IsFirmwarePayload,omitempty"`
	IsLoadedByiBoot             bool   `json:"is_loaded_byi_boot,omitempty" mapstructure:"IsLoadedByiBoot,omitempty"`
	IsLoadedByiBootStage1       bool   `json:"is_loaded_byi_boot_stage_1,omitempty" mapstructure:"IsLoadedByiBootStage1,omitempty"`
	IsiBootEANFirmware          bool   `json:"isi_boot_ean_firmware,omitempty" mapstructure:"IsiBootEANFirmware,omitempty"`
	IsiBootNonEssentialFirmware bool   `json:"isi_boot_non_essential_firmware,omitempty" mapstructure:"IsiBootNonEssentialFirmware,omitempty"`
	Path                        string `plist:"Path" json:"path,omitempty" mapstructure:"Path,omitempty"`
	Personalize                 bool   `json:"personalize,omitempty" mapstructure:"Personalize,omitempty"`
	RestoreRequestRules         []any  `json:"restore_request_rules,omitempty" mapstructure:"RestoreRequestRules,omitempty"`
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
		if _, ok := bID.Manifest["KernelCache"]; !ok {
			continue
		}
		if !utils.StrSliceHas(kernelCaches[bID.Info.DeviceClass], bID.Manifest["KernelCache"].Info["Path"].(string)) {
			kernelCaches[bID.Info.DeviceClass] = append(kernelCaches[bID.Info.DeviceClass], bID.Manifest["KernelCache"].Info["Path"].(string))
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
		if ibec, ok := bID.Manifest["iBEC"]; ok {
			if !utils.StrSliceHas(bootLoaders[bID.Info.DeviceClass], ibec.Info["Path"].(string)) {
				if len(ibec.Info["Path"].(string)) > 0 {
					bootLoaders[bID.Info.DeviceClass] = append(bootLoaders[bID.Info.DeviceClass], ibec.Info["Path"].(string))
				}
			}
		}
		if iboot, ok := bID.Manifest["iBoot"]; ok {
			if !utils.StrSliceHas(bootLoaders[bID.Info.DeviceClass], iboot.Info["Path"].(string)) {
				if len(iboot.Info["Path"].(string)) > 0 {
					bootLoaders[bID.Info.DeviceClass] = append(bootLoaders[bID.Info.DeviceClass], iboot.Info["Path"].(string))
				}
			}
		}
		if ibss, ok := bID.Manifest["iBSS"]; ok {
			if !utils.StrSliceHas(bootLoaders[bID.Info.DeviceClass], ibss.Info["Path"].(string)) {
				if len(ibss.Info["Path"].(string)) > 0 {
					bootLoaders[bID.Info.DeviceClass] = append(bootLoaders[bID.Info.DeviceClass], ibss.Info["Path"].(string))
				}
			}
		}
		if llb, ok := bID.Manifest["LLB"]; ok {
			if !utils.StrSliceHas(bootLoaders[bID.Info.DeviceClass], llb.Info["Path"].(string)) {
				if len(llb.Info["Path"].(string)) > 0 {
					bootLoaders[bID.Info.DeviceClass] = append(bootLoaders[bID.Info.DeviceClass], llb.Info["Path"].(string))
				}
			}
		}
		if sep, ok := bID.Manifest["SEP"]; ok {
			if !utils.StrSliceHas(bootLoaders[bID.Info.DeviceClass], sep.Info["Path"].(string)) {
				if len(sep.Info["Path"].(string)) > 0 {
					bootLoaders[bID.Info.DeviceClass] = append(bootLoaders[bID.Info.DeviceClass], sep.Info["Path"].(string))
				}
			}
		}
	}
	return bootLoaders
}

func (b *BuildManifest) GetBuildIdentity(device string) (*BuildIdentity, error) {
	for _, bID := range b.BuildIdentities {
		if strings.EqualFold(bID.ApProductType, device) {
			return &bID, nil
		}
	}
	return nil, fmt.Errorf("failed to find build identity for device %s", device)
}
