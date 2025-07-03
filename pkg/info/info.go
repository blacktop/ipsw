package info

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/devicetree"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/blacktop/ipsw/pkg/xcode"
	"github.com/pkg/errors"
)

var (
	//go:embed data/procs.gz
	procsData []byte
	//go:embed data/firmware_keys.gz
	keysJSONData []byte
	//go:embed data/t8030_ap_keys.gz
	t8030APKeysJSONData []byte // credit - https://gist.github.com/NyanSatan/2b8c2d6d37da5a04a222469987fcfa2b - A13 Bionic
	//go:embed data/t8101_ap_keys.gz
	t8101APKeysJSONData []byte // credit - https://gist.github.com/NyanSatan/fd627adebaa4120269754cd613e81877 - A14 Bionic
	//go:embed data/t8103_ap_keys.gz
	t8103APKeysJSONData []byte // credit - https://gist.github.com/NyanSatan/a12ff77d9cf38fa70e6238794896093d - M1
)

var ErrorCryptexNotFound = errors.New("cryptex not found")

type apKey struct {
	Device   string `json:"device,omitempty"`
	Build    string `json:"build,omitempty"`
	Type     string `json:"type,omitempty"`
	Filename string `json:"filename,omitempty"`
	File     string `json:"file,omitempty"`
	IPSW     string `json:"fw,omitempty"`
	KBag     string `json:"kbag,omitempty"`
	Key      string `json:"key,omitempty"`
}

func (a apKey) Name() string {
	if len(a.Filename) == 0 {
		return a.File
	}
	return a.Filename
}

// Info in the info object
type Info struct {
	Plists      *plist.Plists
	DeviceTrees map[string]*devicetree.DeviceTree
}

type processors struct {
	Name          string
	Model         string
	Semiconductor string
	DieSize       string
	Transistors   string
	CPUISA        string
	CPU           string
	CPUID         string
	CPUCache      []string
	GPU           string
	AIAccelerator string
	Memory        string
	Introduced    string
	Devices       []string
}

type ProcessorDB []processors

func GetProcessorDB() (*ProcessorDB, error) {
	var ps ProcessorDB

	zr, err := gzip.NewReader(bytes.NewReader(procsData))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	if err := json.NewDecoder(zr).Decode(&ps); err != nil {
		return nil, fmt.Errorf("failed unmarshaling procs.gz data: %w", err)
	}

	return &ps, nil
}

func (p *ProcessorDB) GetProcessor(cpuid string) (*processors, error) {
	for _, proc := range *p {
		if strings.EqualFold(proc.CPUID, cpuid) {
			return &proc, nil
		}
	}
	return nil, fmt.Errorf("failed to find processor for '%s'", cpuid)
}

// getProcessors reads the processors from embedded JSON
func getProcessor(cpuid string) (processors, error) {
	var ps []processors

	zr, err := gzip.NewReader(bytes.NewReader(procsData))
	if err != nil {
		return processors{}, err
	}
	defer zr.Close()

	if err := json.NewDecoder(zr).Decode(&ps); err != nil {
		return processors{}, fmt.Errorf("failed unmarshaling procs.gz data: %w", err)
	}

	for _, p := range ps {
		if strings.EqualFold(p.CPUID, cpuid) {
			return p, nil
		}
	}

	return processors{}, fmt.Errorf("failed to find processor for %s", cpuid)
}

func getFirmwareKeys(device, build string) (map[string]string, error) {
	var keys map[string]map[string]map[string]string

	zr, err := gzip.NewReader(bytes.NewReader(keysJSONData))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	if err := json.NewDecoder(zr).Decode(&keys); err != nil {
		return nil, fmt.Errorf("failed unmarshaling firmware_keys.gz data: %w", err)
	}

	return keys[device][build], nil
}

func getApFirmwareKey(device, build, filename string) (string, string, error) {
	var m1Keys []apKey
	var a13Keys []apKey
	var a14Keys []apKey

	zr1, err := gzip.NewReader(bytes.NewReader(t8030APKeysJSONData))
	if err != nil {
		return "", "", err
	}
	defer zr1.Close()

	if err := json.NewDecoder(zr1).Decode(&a13Keys); err != nil {
		return "", "", fmt.Errorf("failed unmarshaling t8030_ap_keys.gz data: %w", err)
	}

	for _, key := range a13Keys {
		if key.Device == device && key.Build == build && key.Filename == filename {
			return key.KBag, key.Key, nil
		}
	}

	zr2, err := gzip.NewReader(bytes.NewReader(t8101APKeysJSONData))
	if err != nil {
		return "", "", err
	}
	defer zr2.Close()

	if err := json.NewDecoder(zr2).Decode(&a14Keys); err != nil {
		return "", "", fmt.Errorf("failed unmarshaling t8101_ap_keys.gz data: %w", err)
	}

	for _, key := range a14Keys {
		if key.Device == device && key.Build == build && key.Filename == filename {
			return key.KBag, key.Key, nil
		}
	}

	zr3, err := gzip.NewReader(bytes.NewReader(t8103APKeysJSONData))
	if err != nil {
		return "", "", err
	}
	defer zr3.Close()

	if err := json.NewDecoder(zr3).Decode(&m1Keys); err != nil {
		return "", "", fmt.Errorf("failed unmarshaling t8101_ap_keys.gz data: %w", err)
	}

	for _, key := range m1Keys {
		if key.Name() == filename {
			return key.KBag, key.Key, nil
		}
	}

	return "", "", fmt.Errorf("failed to find key for device: %s, build: %s, filename: %s", device, build, filename)
}

func (i *Info) String() string {
	var iStr string
	var verextra string
	if i.Plists.OTAInfo != nil {
		verextra = fmt.Sprintf(" %s", i.Plists.OTAInfo.MobileAssetProperties.ProductVersionExtra)
	}
	if i.Plists.BuildManifest != nil {
		iStr += fmt.Sprintf(
			"Version        = %s\n"+
				"BuildVersion   = %s\n"+
				"OS Type        = %s\n",
			i.Plists.BuildManifest.ProductVersion+verextra,
			i.Plists.BuildManifest.ProductBuildVersion,
			i.Plists.GetOSType(),
		)
	}
	if i.Plists.Restore != nil {
		foundFS := false
		if fsDMG, err := i.GetFileSystemOsDmg(); err == nil {
			foundFS = true
			iStr += fmt.Sprintf("FileSystem     = %s\n", fsDMG)
		}
		if fsDMG, err := i.GetSystemOsDmg(); err == nil {
			iStr += fmt.Sprintf("SystemOS       = %s\n", fsDMG)
		}
		if fsDMG, err := i.GetAppOsDmg(); err == nil {
			iStr += fmt.Sprintf("AppOS          = %s\n", fsDMG)
		}
		if fsDMG, err := i.GetExclaveOSDmg(); err == nil {
			iStr += fmt.Sprintf("ExclaveOS      = %s\n", fsDMG)
		}
		if ramDisk, err := i.GetRestoreRamDiskDmgs(); err == nil {
			iStr += fmt.Sprintf("RestoreRamDisk = %s\n", ramDisk)
		}
		if !foundFS {
			if len(i.Plists.Restore.SystemRestoreImageFileSystems) > 0 {
				for file, fsType := range i.Plists.Restore.SystemRestoreImageFileSystems {
					iStr += fmt.Sprintf("FileSystem     = %s (Type: %s)\n", file, fsType)
				}
			}
		}
	}
	if i.Plists.OTAInfo != nil {
		if len(i.Plists.OTAInfo.MobileAssetProperties.RestoreVersion) > 0 {
			iStr += fmt.Sprintf("RestoreVersion = %s\n", i.Plists.OTAInfo.MobileAssetProperties.RestoreVersion)
		}
		if len(i.Plists.OTAInfo.MobileAssetProperties.PrerequisiteBuild) > 0 {
			iStr += fmt.Sprintf("PrereqBuild    = %s\n", i.Plists.OTAInfo.MobileAssetProperties.PrerequisiteBuild)
		}
		if i.Plists.OTAInfo.MobileAssetProperties.SplatOnly {
			iStr += "IsRSR          = ✅\n"
		}
	}
	if len(i.DeviceTrees) > 0 {
		kcs := i.Plists.BuildManifest.GetKernelCaches()
		bls := i.Plists.BuildManifest.GetBootLoaders()
		iStr += "\nDevices\n"
		iStr += "-------\n"
		for _, dtree := range i.DeviceTrees {
			dt, _ := dtree.Summary()
			prodName := dt.ProductName
			if len(prodName) == 0 {
				devices, err := xcode.GetDevices()
				if err == nil {
					for _, device := range devices {
						if device.ProductType == dt.ProductType {
							prodName = device.ProductDescription
							break
						}
					}
				} else {
					prodName = dt.ProductType
				}
			}
			iStr += fmt.Sprintf("\n%s\n", prodName)
			iStr += fmt.Sprintf(" > %s_%s_%s\n", dt.ProductType, strings.ToUpper(dt.BoardConfig), i.Plists.BuildManifest.ProductBuildVersion)
			if !dt.Timestamp.IsZero() {
				iStr += fmt.Sprintf("   - TimeStamp: %s\n", dt.Timestamp.Format("02 Jan 2006 15:04:05 MST"))
			}
			if len(kcs[strings.ToLower(dt.BoardConfig)]) > 0 {
				iStr += fmt.Sprintf("   - KernelCache: %s\n", strings.Join(kcs[strings.ToLower(dt.BoardConfig)], ", "))
			}
			if cpu := i.GetCPU(dt.BoardConfig); len(cpu) > 0 {
				iStr += fmt.Sprintf("   - %s\n", cpu)
			}
			if len(bls[strings.ToLower(dt.BoardConfig)]) > 0 {
				iStr += "   - BootLoaders\n"
				for _, bl := range bls[strings.ToLower(dt.BoardConfig)] {
					iStr += fmt.Sprintf("       * %s\n", filepath.Base(bl))
				}
			}
		}
	} else {
		if i.Plists.BuildManifest != nil {
			iStr += "\nDevices\n"
			iStr += "-------\n"
			for _, dev := range i.Plists.BuildManifest.SupportedProductTypes {
				iStr += fmt.Sprintf(" > %s_%s\n", dev, i.Plists.BuildManifest.ProductBuildVersion)
			}
		}
	}
	return iStr
}

type InfoJSON struct {
	Type    string `json:"type,omitempty"`
	Version string `json:"version,omitempty"`
	Build   string `json:"build,omitempty"`
	OS      string `json:"os,omitempty"`
	Devices any    `json:"devices,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (i *Info) ToJSON() InfoJSON {
	if i.Plists.BuildIdentities == nil {
		return InfoJSON{Error: "no BuildManifest.plist found"}
	}
	return InfoJSON{
		Type:    i.Plists.Type,
		Version: i.Plists.BuildManifest.ProductVersion,
		Build:   i.Plists.BuildManifest.ProductBuildVersion,
		OS:      i.Plists.GetOSType(),
		Devices: func() any {
			if len(i.DeviceTrees) > 0 {
				var devs []struct {
					Name      string `json:"name,omitempty"`
					Product   string `json:"product,omitempty"`
					Board     string `json:"board,omitempty"`
					Timestamp string `json:"timestamp,omitempty"`
					CPU       string `json:"cpu,omitempty"`
				}
				for _, dtree := range i.DeviceTrees {
					dt, _ := dtree.Summary()
					devs = append(devs, struct {
						Name      string `json:"name,omitempty"`
						Product   string `json:"product,omitempty"`
						Board     string `json:"board,omitempty"`
						Timestamp string `json:"timestamp,omitempty"`
						CPU       string `json:"cpu,omitempty"`
					}{
						Name:      dt.ProductName,
						Product:   dt.ProductType,
						Board:     dt.BoardConfig,
						Timestamp: dt.Timestamp.Format("02 Jan 2006 15:04:05 MST"),
						CPU:       i.GetCPU(dt.BoardConfig),
					})
				}
				return devs
			} else {
				return i.Plists.MobileAssetProperties.SupportedDevices
			}
		}(),
	}
}

// GetAppOsDmg returns the name of the AppOS dmg
func (i *Info) GetAppOsDmg() (string, error) {
	var dmgs []string
	if i.Plists != nil && i.Plists.BuildManifest != nil {
		for _, bi := range i.Plists.BuildIdentities {
			if appOS, ok := bi.Manifest["Cryptex1,AppOS"]; ok {
				dmgs = append(dmgs, appOS.Info["Path"].(string))
			}
		}
		dmgs = utils.Unique(dmgs)
		if len(dmgs) == 0 {
			return "", fmt.Errorf("no AppOS DMG found: %w", ErrorCryptexNotFound)
		} else if len(dmgs) == 1 {
			return dmgs[0], nil
		} else {
			return "", fmt.Errorf("multiple AppOS DMGs found")
		}
	}
	return "", fmt.Errorf("no BuildManifest.plist found")
}

// GetSystemOsDmg returns the name of the SystemOS dmg (the one with the dyld_shared_cache(s))
func (i *Info) GetSystemOsDmg() (string, error) {
	var dmgs []string
	if i.Plists != nil && i.Plists.BuildManifest != nil {
		for _, bi := range i.Plists.BuildIdentities {
			if sysOS, ok := bi.Manifest["Cryptex1,SystemOS"]; ok {
				return sysOS.Info["Path"].(string), nil
			}
		}
		dmgs = utils.Unique(dmgs)
		if len(dmgs) == 0 {
			return "", fmt.Errorf("no SystemOS DMG found: %w", ErrorCryptexNotFound)
		} else if len(dmgs) == 1 {
			return dmgs[0], nil
		} else {
			return "", fmt.Errorf("multiple SystemOS DMGs found")
		}
	}
	return "", fmt.Errorf("no BuildManifest.plist found")
}

// GetFileSystemOsDmg returns the name of the file system dmg
func (i *Info) GetFileSystemOsDmg() (string, error) {
	var dmgs []string
	if i.Plists != nil && i.Plists.BuildManifest != nil {
		for _, bi := range i.Plists.BuildIdentities {
			if fsOS, ok := bi.Manifest["OS"]; ok {
				// log.Debugf("Found: %s", fsOS.Info["Path"].(string))
				if !strings.Contains(bi.Info.Variant, "Recovery") {
					dmgs = append(dmgs, fsOS.Info["Path"].(string))
				}
			}
		}
		dmgs = utils.Unique(dmgs)
		if len(dmgs) == 0 {
			return "", fmt.Errorf("no filesystem DMG found: %w", ErrorCryptexNotFound)
		} else if len(dmgs) == 1 {
			return dmgs[0], nil
		} else {
			return "", fmt.Errorf("multiple filesystem DMGs found")
		}
	} else if i.Plists != nil && i.Plists.Restore != nil {
		if dmg, ok := i.Plists.Restore.SystemRestoreImages["User"]; ok {
			return dmg, nil
		}
		return "", fmt.Errorf("no BuildManifest.plist AND no SystemRestoreImages (used in older IPSWs) found")
	}
	return "", fmt.Errorf("no BuildManifest.plist found")
}

// GetRestoreRamDiskDmgs returns the name of the RestoreRamDisk dmg
func (i *Info) GetRestoreRamDiskDmgs() ([]string, error) {
	var dmgs []string
	if i.Plists != nil && i.Plists.BuildManifest != nil {
		for _, bi := range i.Plists.BuildIdentities {
			if rrdisk, ok := bi.Manifest["RestoreRamDisk"]; ok {
				dmgs = append(dmgs, rrdisk.Info["Path"].(string))
			}
		}
		dmgs = utils.Unique(dmgs)
	}
	if len(dmgs) > 0 {
		return dmgs, nil
	}
	return nil, fmt.Errorf("no RestoreRamDisk DMG found")
}

func (i *Info) GetExclaveOSDmg() (string, error) {
	var dmgs []string
	if i.Plists != nil && i.Plists.BuildManifest != nil {
		for _, bi := range i.Plists.BuildIdentities {
			if appOS, ok := bi.Manifest["Ap,ExclaveOS"]; ok {
				dmgs = append(dmgs, appOS.Info["Path"].(string))
			}
		}
		dmgs = utils.Unique(dmgs)
		if len(dmgs) == 0 {
			return "", fmt.Errorf("no ExclaveOS DMG found: %w", ErrorCryptexNotFound)
		} else if len(dmgs) == 1 {
			return dmgs[0], nil
		} else {
			return "", fmt.Errorf("multiple ExclaveOS DMGs found")
		}
	}
	return "", fmt.Errorf("no BuildManifest.plist found")
}

func (i *Info) IsMacOS() bool {
	for _, dev := range i.Plists.BuildManifest.SupportedProductTypes {
		if strings.Contains(dev, "Mac") {
			return true
		}
	}
	return false
}

// GetOsDmg returns the name of the OS dmg
func (i *Info) GetCPU(board string) string {
	if i.Plists.Restore != nil {
		for _, device := range i.Plists.Restore.DeviceMap {
			if strings.EqualFold(device.BoardConfig, board) {
				if proc, err := getProcessor(device.Platform); err == nil {
					return fmt.Sprintf("CPU: %s (%s), ID: %s", proc.Name, proc.CPUISA, device.Platform)
				} else {
					return fmt.Sprintf("ID: %s", device.Platform)
				}
			}
		}
	} else if i.Plists.BuildManifest != nil {
		for _, ident := range i.Plists.BuildIdentities {
			if strings.EqualFold(ident.Info.DeviceClass, board) {
				plat := "t" + strings.TrimPrefix(ident.ApChipID, "0x")
				if proc, err := getProcessor(plat); err == nil {
					return fmt.Sprintf("CPU: %s (%s), ID: %s", proc.Name, proc.CPUISA, plat)
				} else {
					return fmt.Sprintf("AP ChipID: %s", ident.ApChipID)
				}
			}
		}
	}
	return ""
}

// GetFolder returns a folder name for all the devices included in an IPSW
func (i *Info) GetFolder(device ...string) (string, error) {
	if i.Plists.BuildManifest == nil {
		if i.Plists.Type == "OTA" && i.Plists.OTAInfo.CFBundleName == "SimulatorRuntimeAsset" {
			typ, found := strings.CutPrefix(i.Plists.OTAInfo.CFBundleIdentifier, "com.apple.MobileAsset.")
			if !found {
				typ = "Simulator"
			}
			return fmt.Sprintf("%s_%s_%s",
				i.Plists.OTAInfo.MobileAssetProperties.SimulatorVersion,
				i.Plists.OTAInfo.MobileAssetProperties.Build,
				typ,
			), nil
		}
		return "", fmt.Errorf("no BuildManifest.plist found")
	}

	var dev string
	if len(device) > 0 && len(device[0]) > 0 {
		dev = device[0]
	}

	var devs []string
	if len(i.DeviceTrees) > 0 {
		for _, dtree := range i.DeviceTrees {
			dt, err := dtree.Summary()
			if err != nil {
				log.Fatal(err.Error())
			}
			devs = append(devs, dt.ProductType)
		}

		devs = utils.SortDevices(utils.Unique(devs))

		if len(dev) > 0 {
			if slices.Contains(devs, dev) {
				return fmt.Sprintf("%s__%s", i.Plists.BuildManifest.ProductBuildVersion, dev), nil
			} else {
				return "", fmt.Errorf("device '%s' not found in IPSW/OTA", dev)
			}
		}

		return fmt.Sprintf("%s__%s", i.Plists.BuildManifest.ProductBuildVersion, getAbbreviatedDevListFolder(devs)), nil
	}

	sort.Strings(i.Plists.BuildManifest.SupportedProductTypes)
	return fmt.Sprintf("%s__%s", i.Plists.BuildManifest.ProductBuildVersion, getAbbreviatedDevListFolder(i.Plists.BuildManifest.SupportedProductTypes)), nil
}

// GetFolders returns a list of the IPSW name folders
func (i *Info) GetFolders() ([]string, error) {
	if i.Plists.BuildManifest == nil {
		return nil, fmt.Errorf("no BuildManifest.plist found")
	}
	var folders []string
	if len(i.DeviceTrees) > 0 {
		for _, dtree := range i.DeviceTrees {
			dt, _ := dtree.Summary()
			folders = append(folders, fmt.Sprintf("%s_%s_%s", dt.ProductType, strings.ToUpper(dt.BoardConfig), i.Plists.BuildManifest.ProductBuildVersion))
		}
		return folders, nil
	}
	return nil, fmt.Errorf("no devices found")
}

// GetFolderForFile returns a list of the IPSW name folders for a given file
func (i *Info) GetFolderForFile(fileName string) (string, error) {
	if i.Plists.BuildManifest == nil {
		return "", fmt.Errorf("no BuildManifest.plist found")
	}
	if len(i.DeviceTrees) > 0 {
		files := i.getManifestPaths()
		for _, dtree := range i.DeviceTrees {
			dt, _ := dtree.Summary()
			for _, file := range files[strings.ToLower(dt.BoardConfig)] {
				if strings.Contains(fileName, filepath.Base(file)) {
					return fmt.Sprintf("%s_%s_%s", dt.ProductType, strings.ToUpper(dt.BoardConfig), i.Plists.BuildManifest.ProductBuildVersion), nil
				}
			}
		}
	}
	return "", fmt.Errorf("no devices found")
}

func (i *Info) getManifestPaths() map[string][]string {

	files := make(map[string][]string, len(i.Plists.BuildIdentities))

	for _, bID := range i.Plists.BuildIdentities {
		for _, manifest := range bID.Manifest {
			if len(manifest.Info["Path"].(string)) > 0 {
				files[bID.Info.DeviceClass] = append(files[bID.Info.DeviceClass], manifest.Info["Path"].(string))
			}
		}
	}

	return files
}

type folder struct {
	Name         string
	KernelCaches []string
}

func (i *Info) getFolders() ([]folder, error) {
	if i.Plists.BuildManifest == nil {
		return nil, fmt.Errorf("no BuildManifest.plist found")
	}
	if len(i.DeviceTrees) > 0 {
		var fs []folder
		kcs := i.Plists.BuildManifest.GetKernelCaches()
		for _, dtree := range i.DeviceTrees {
			dt, _ := dtree.Summary()
			fs = append(fs, folder{
				Name:         fmt.Sprintf("%s_%s_%s", dt.ProductType, strings.ToUpper(dt.BoardConfig), i.Plists.BuildManifest.ProductBuildVersion),
				KernelCaches: kcs[strings.ToLower(dt.BoardConfig)],
			})
		}
		return fs, nil
	}
	return nil, fmt.Errorf("no devices found")
}

// GetKernelCacheFolders returns the folders belonging to a KernelCache
func (i *Info) GetKernelCacheFolders(kc string) ([]string, error) {
	var folders []string
	fds, err := i.getFolders()
	if err != nil {
		return nil, fmt.Errorf("failed to get folders: %v", err)
	}
	for _, folder := range fds {
		for _, kcache := range folder.KernelCaches {
			if strings.HasSuffix(kc, kcache) {
				folders = append(folders, folder.Name)
			}
		}
	}
	return folders, nil
}

// GetKernelCacheFileName returns a short new kernelcache name including all the supported devices
func (i *Info) GetKernelCacheFileName(kc string) string {
	devList := getAbbreviatedDevList(i.GetDevicesForKernelCache(filepath.Base(kc)))
	if len(devList) == 0 {
		return filepath.Base(kc)
	}
	return fmt.Sprintf("%s.%s", strings.TrimSuffix(filepath.Base(kc), filepath.Ext(kc)), devList)
}

// GetDevicesForKernelCache returns a sorted array of devices that support the kernelcache
func (i *Info) GetDevicesForKernelCache(kc string) []string {
	var devices []string

	for bconf, kcache := range i.Plists.BuildManifest.GetKernelCaches() {
		if utils.StrSliceHas(kcache, filepath.Base(kc)) {
			for _, dtree := range i.DeviceTrees {
				dt, _ := dtree.Summary()
				if strings.EqualFold(bconf, dt.BoardConfig) {
					devices = append(devices, dt.ProductType)
				}
			}
		}
	}

	return utils.SortDevices(utils.Unique(devices))
}

func getAbbreviatedDevList(devices []string) string {
	var devList string

	if len(devices) == 0 {
		return ""
	} else if len(devices) == 1 {
		return devices[0]
	}

	currentDev := devices[0]
	devPrefix := strings.Split(currentDev, ",")[0]
	devList += currentDev

	for _, dev := range devices[1:] {
		if strings.HasPrefix(dev, devPrefix) {
			devList += fmt.Sprintf("_%s", strings.Split(dev, ",")[1])
		} else {
			currentDev = dev
			devPrefix = strings.Split(currentDev, ",")[0]
			devList += "_" + currentDev
		}
	}

	return devList
}

func getAbbreviatedDevListFolder(devices []string) string {
	var devList string

	if len(devices) == 0 {
		return ""
	} else if len(devices) == 1 {
		return devices[0]
	} else if strings.Contains(devices[0], "Mac") {
		return "MacOS"
	}

	currentDev := devices[0]
	devPrefix := strings.Split(currentDev, ",")[0]
	devList += currentDev

	for _, dev := range devices[1:] {
		if strings.HasPrefix(dev, devPrefix) {
			devList += fmt.Sprintf("_%s", strings.Split(dev, ",")[1])
		} else {
			currentDev = dev
			devPrefix = strings.Split(currentDev, ",")[0]
			devList += "_" + currentDev
		}
	}

	return devList
}

// Parse parses plist files in a local ipsw file
func Parse(ipswPath string, keys ...string) (*Info, error) {
	var err error

	i := &Info{}

	i.Plists, err = plist.Parse(ipswPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse plists: %v", err)
	}
	i.DeviceTrees, err = devicetree.Parse(ipswPath, keys...)
	if err != nil {
		if errors.Is(err, devicetree.ErrEncryptedDeviceTree) { // FIXME: this is a hack to avoid stopping the parsing of the metadata info
			log.Error(err.Error())
		} else {
			log.Errorf("failed to parse devicetree: %v", err)
		}
	}

	return i, nil
}

// ParseZipFiles parses plist files and devicetree in a remote zip file
func ParseZipFiles(files []*zip.File, keys ...string) (*Info, error) {
	var err error

	i := &Info{}

	i.Plists, err = plist.ParseZipFiles(files)
	if err != nil {
		return nil, fmt.Errorf("failed to parse plists: %v", err)
	}
	i.DeviceTrees, err = devicetree.ParseZipFiles(files, keys...)
	if err != nil {
		if errors.Is(err, devicetree.ErrEncryptedDeviceTree) { // FIXME: this is a hack to avoid stopping the parsing of the metadata info
			log.Error(err.Error())
		} else {
			log.Errorf("failed to parse devicetree: %v", err)
		}
	}

	return i, nil
}

func ParseOTAFiles(files []fs.File) (*Info, error) {
	var err error

	i := &Info{}

	i.DeviceTrees = make(map[string]*devicetree.DeviceTree)

	i.Plists, err = plist.ParsePlistFiles(files)
	if err != nil {
		return nil, fmt.Errorf("failed to parse plists: %v", err)
	}
	for _, f := range files {
		fi, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("failed to get file info: %v", err)
		}
		if filepath.Ext(fi.Name()) == ".im4p" {
			dat, err := io.ReadAll(f)
			if err != nil {
				return nil, fmt.Errorf("failed to read file: %v", err)
			}
			dt, err := devicetree.ParseImg4Data(dat)
			if err != nil {
				if errors.Is(err, devicetree.ErrEncryptedDeviceTree) { // FIXME: this is a hack to avoid stopping the parsing of the metadata info
					log.Error(err.Error())
				} else {
					log.Errorf("failed to parse devicetree: %v", err)
				}
			}
			i.DeviceTrees[fi.Name()] = dt
		}
	}

	return i, nil
}
