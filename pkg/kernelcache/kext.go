package kernelcache

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-plist"
)

const tagPtrMask = 0xffff000000000000

type PrelinkInfo struct {
	PrelinkInfoDictionary []CFBundle `plist:"_PrelinkInfoDictionary,omitempty" json:"prelink_info_dictionary,omitempty"`
}

type CFBundle struct {
	ID   string `plist:"CFBundleIdentifier,omitempty" json:"id,omitempty"`
	Name string `plist:"CFBundleName,omitempty" json:"name,omitempty"`

	SDK                 string   `plist:"DTSDKName,omitempty" json:"sdk,omitempty"`
	SDKBuild            string   `plist:"DTSDKBuild,omitempty" json:"sdk_build,omitempty"`
	Xcode               string   `plist:"DTXcode,omitempty" json:"xcode,omitempty"`
	XcodeBuild          string   `plist:"DTXcodeBuild,omitempty" json:"xcode_build,omitempty"`
	Copyright           string   `plist:"NSHumanReadableCopyright,omitempty" json:"copyright,omitempty"`
	BuildMachineOSBuild string   `plist:"BuildMachineOSBuild,omitempty" json:"build_machine_os_build,omitempty"`
	DevelopmentRegion   string   `plist:"CFBundleDevelopmentRegion,omitempty" json:"development_region,omitempty"`
	PlatformName        string   `plist:"DTPlatformName,omitempty" json:"platform_name,omitempty"`
	PlatformVersion     string   `plist:"DTPlatformVersion,omitempty" json:"platform_version,omitempty"`
	PlatformBuild       string   `plist:"DTPlatformBuild,omitempty" json:"platform_build,omitempty"`
	PackageType         string   `plist:"CFBundlePackageType,omitempty" json:"package_type,omitempty"`
	Version             string   `plist:"CFBundleVersion,omitempty" json:"version,omitempty"`
	ShortVersionString  string   `plist:"CFBundleShortVersionString,omitempty" json:"short_version_string,omitempty"`
	CompatibleVersion   string   `plist:"OSBundleCompatibleVersion,omitempty" json:"compatible_version,omitempty"`
	MinimumOSVersion    string   `plist:"MinimumOSVersion,omitempty" json:"minimum_os_version,omitempty"`
	SupportedPlatforms  []string `plist:"CFBundleSupportedPlatforms,omitempty" json:"supported_platforms,omitempty"`
	Signature           string   `plist:"CFBundleSignature,omitempty" json:"signature,omitempty"`

	IOKitPersonalities map[string]any    `plist:"IOKitPersonalities,omitempty" json:"io_kit_personalities,omitempty"`
	OSBundleLibraries  map[string]string `plist:"OSBundleLibraries,omitempty" json:"os_bundle_libraries,omitempty"`
	UIDeviceFamily     []int             `plist:"UIDeviceFamily,omitempty" json:"ui_device_family,omitempty"`

	OSBundleRequired             string   `plist:"OSBundleRequired,omitempty" json:"os_bundle_required,omitempty"`
	UIRequiredDeviceCapabilities []string `plist:"UIRequiredDeviceCapabilities,omitempty" json:"ui_required_device_capabilities,omitempty"`

	AppleSecurityExtension bool `plist:"AppleSecurityExtension,omitempty" json:"apple_security_extension,omitempty"`

	InfoDictionaryVersion string `plist:"CFBundleInfoDictionaryVersion,omitempty" json:"info_dictionary_version,omitempty"`
	OSKernelResource      bool   `plist:"OSKernelResource,omitempty" json:"os_kernel_resource,omitempty"`
	GetInfoString         string `plist:"CFBundleGetInfoString,omitempty" json:"get_info_string,omitempty"`
	AllowUserLoad         bool   `plist:"OSBundleAllowUserLoad,omitempty" json:"allow_user_load,omitempty"`
	ExecutableLoadAddr    uint64 `plist:"_PrelinkExecutableLoadAddr,omitempty" json:"executable_load_addr,omitempty"`

	ModuleIndex  uint64 `plist:"ModuleIndex,omitempty" json:"module_index,omitempty"`
	Executable   string `plist:"CFBundleExecutable,omitempty" json:"executable,omitempty"`
	BundlePath   string `plist:"_PrelinkBundlePath,omitempty" json:"bundle_path,omitempty"`
	RelativePath string `plist:"_PrelinkExecutableRelativePath,omitempty" json:"relative_path,omitempty"`
}

type KmodInfoT struct {
	NextAddr          uint64
	InfoVersion       int32
	ID                uint32
	Name              [64]byte
	Version           [64]byte
	ReferenceCount    int32  // # linkage refs to this
	ReferenceListAddr uint64 // who this refs (links on)
	Address           uint64 // starting address
	Size              uint64 // total size
	HeaderSize        uint64 // unwired hdr size
	StartAddr         uint64
	StopAddr          uint64
}

func (i KmodInfoT) String() string {
	return fmt.Sprintf("id: %#x, name: %s, version: %s, ref_cnt: %d, ref_list: %#x, addr: %#x, size: %#x, header_size: %#x, start: %#x, stop: %#x, next: %#x, info_ver: %d",
		i.ID,
		string(i.Name[:]),
		string(i.Version[:]),
		i.ReferenceCount,
		i.ReferenceListAddr,
		i.Address,
		i.Size,
		i.HeaderSize,
		i.StartAddr,
		i.StopAddr,
		i.NextAddr,
		i.InfoVersion,
	)
}

func GetKextStartVMAddrs(m *macho.File) ([]uint64, error) {
	if kmodStart := m.Section("__PRELINK_INFO", "__kmod_start"); kmodStart != nil {
		data, err := kmodStart.Data()
		if err != nil {
			return nil, err
		}
		ptrs := make([]uint64, kmodStart.Size/8)
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &ptrs); err != nil {
			return nil, err
		}
		return ptrs, nil
	}
	return nil, fmt.Errorf("section __PRELINK_INFO.__kmod_start not found")
}

func GetKextInfos(m *macho.File) ([]KmodInfoT, error) {
	var infos []KmodInfoT
	if kmodStart := m.Section("__PRELINK_INFO", "__kmod_info"); kmodStart != nil {
		data, err := kmodStart.Data()
		if err != nil {
			return nil, err
		}
		ptrs := make([]uint64, kmodStart.Size/8)
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &ptrs); err != nil {
			return nil, err
		}
		for _, ptr := range ptrs {
			// fmt.Printf("ptr: %#x, untagged: %#x\n", ptr, unTag(ptr))
			off, err := m.GetOffset(ptr | tagPtrMask)
			if err != nil {
				return nil, err
			}
			info := KmodInfoT{}
			infoBytes := make([]byte, binary.Size(info))
			_, err = m.ReadAt(infoBytes, int64(off))
			if err != nil {
				return nil, err
			}

			if err := binary.Read(bytes.NewReader(infoBytes), binary.LittleEndian, &info); err != nil {
				return nil, fmt.Errorf("failed to read KmodInfoT at %#x: %v", off, err)
			}

			// fixups
			info.StartAddr = fixupchains.DyldChainedPtr64KernelCacheRebase{Pointer: info.StartAddr}.Target() + m.GetBaseAddress()
			info.StopAddr = fixupchains.DyldChainedPtr64KernelCacheRebase{Pointer: info.StopAddr}.Target() + m.GetBaseAddress()

			infos = append(infos, info)
		}
		return infos, nil
	}
	return nil, fmt.Errorf("section __PRELINK_INFO.__kmod_start not found")
}

func GetKexts(kernel *macho.File) ([]CFBundle, error) {
	if infoSec := kernel.Section("__PRELINK_INFO", "__info"); infoSec != nil {

		data, err := infoSec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read __PRELINK_INFO.__info section: %v", err)
		}

		var prelink PrelinkInfo
		decoder := plist.NewDecoder(bytes.NewReader(bytes.Trim([]byte(data), "\x00")))
		err = decoder.Decode(&prelink)
		if err != nil {
			return nil, fmt.Errorf("failed to decode __PRELINK_INFO.__info section: %v", err)
		}
		return prelink.PrelinkInfoDictionary, nil
	}
	return nil, fmt.Errorf("section __PRELINK_INFO.__info not found")
}

// KextList lists all the kernel extensions in the kernelcache
func KextList(m *macho.File, diffable bool) ([]string, error) {
	var out []string

	bundles, err := GetKexts(m)
	if err != nil {
		return nil, err
	}

	kextStartAdddrs, err := GetKextStartVMAddrs(m)
	if err != nil {
		log.Debugf("failed to get kext start addresses: %v", err)
	}

	if diffable {
		for _, bundle := range bundles {
			out = append(out, fmt.Sprintf("%s (%s)", bundle.ID, bundle.Version))
		}
	} else {
		for _, bundle := range bundles {
			var b string
			if !bundle.OSKernelResource && len(kextStartAdddrs) > 0 {
				b = fmt.Sprintf("%#x: %s", kextStartAdddrs[bundle.ModuleIndex]|tagPtrMask, bundle.ID)
			} else {
				b = fmt.Sprintf("%#x: %s", bundle.ExecutableLoadAddr, bundle.ID)
			}
			if len(bundle.Version) > 0 {
				b += fmt.Sprintf(" (%s)", bundle.Version)
			}
			out = append(out, b)
		}
	}

	sort.Strings(out)

	return out, nil
}

// KextJSON returns the kernel extensions in the kernelcache as a JSON string
func KextJSON(m *macho.File) (string, error) {
	kexts, err := GetKexts(m)
	if err != nil {
		return "", err
	}

	data, err := json.Marshal(kexts)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
