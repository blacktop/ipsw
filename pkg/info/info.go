package info

import (
	"archive/zip"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/devicetree"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/blacktop/ipsw/pkg/xcode"
	"github.com/pkg/errors"
)

var (
	//go:embed data/procs.json
	procsData []byte
	//go:embed data/firmware_keys.json
	keysJsonData []byte
)

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

// getProcessors reads the processors from embedded JSON
func getProcessor(cpuid string) processors {
	var ps []processors

	err := json.Unmarshal(procsData, &ps)
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range ps {
		if strings.ToLower(p.CPUID) == strings.ToLower(cpuid) {
			return p
		}
	}

	return processors{}
}

func getFirmwareKeys(device, build string) map[string]string {
	var keys map[string]map[string]map[string]string

	err := json.Unmarshal(keysJsonData, &keys)
	if err != nil {
		log.Fatal(err)
	}

	return keys[device][build]
}

func (i *Info) String() string {
	var iStr string
	iStr += fmt.Sprintf(
		"Version        = %s\n"+
			"BuildVersion   = %s\n"+
			"OS Type        = %s\n",
		i.Plists.BuildManifest.ProductVersion,
		i.Plists.BuildManifest.ProductBuildVersion,
		i.Plists.GetOSType(),
	)
	if i.Plists.Restore != nil {
		iStr += fmt.Sprintf("FileSystem     = ")
		for file, fsType := range i.Plists.Restore.SystemRestoreImageFileSystems {
			iStr += fmt.Sprintf("%s (Type: %s)\n", file, fsType)
		}
	}
	kcs := i.Plists.BuildManifest.GetKernelCaches()
	iStr += fmt.Sprintf("\nDevices\n")
	iStr += fmt.Sprintf("-------\n")
	for _, dtree := range i.DeviceTrees {
		dt, _ := dtree.Summary()
		prodName := dt.ProductName
		if len(prodName) == 0 {
			devices, err := xcode.GetDevices()
			if err == nil {
				for _, device := range devices {
					if device.ProductType == dt.Model {
						prodName = device.ProductDescription
						break
					}
				}
			} else {
				prodName = dt.Model
			}
		}
		iStr += fmt.Sprintf("\n%s\n", prodName)
		iStr += fmt.Sprintf(" > %s_%s_%s\n", dt.Model, strings.ToUpper(dt.BoardConfig), i.Plists.BuildManifest.ProductBuildVersion)
		iStr += fmt.Sprintf("   - KernelCache: %s\n", kcs[strings.ToLower(dt.BoardConfig)])
		if i.Plists.Restore != nil {
			for _, device := range i.Plists.Restore.DeviceMap {
				if strings.ToLower(device.BoardConfig) == strings.ToLower(dt.BoardConfig) {
					proc := getProcessor(device.Platform)
					iStr += fmt.Sprintf("   - CPU: %s (%s), ID: %s\n", proc.Name, proc.CPUISA, device.Platform)
				}
			}
		}
	}

	return iStr
}

// GetFolder returns a folder name for all the devices included in an IPSW
func (i *Info) GetFolder() string {
	var devs []string
	for _, dtree := range i.DeviceTrees {
		dt, _ := dtree.Summary()
		devs = append(devs, dt.Model)
	}
	devs = utils.SortDevices(utils.Unique(devs))
	return fmt.Sprintf("%s__%s", i.Plists.BuildManifest.ProductBuildVersion, getAbbreviatedDevList(devs))
}

// GetFolders returns a list of the IPSW name folders
func (i *Info) GetFolders() []string {
	var folders []string
	for _, dtree := range i.DeviceTrees {
		dt, _ := dtree.Summary()
		folders = append(folders, fmt.Sprintf("%s_%s_%s", dt.Model, strings.ToUpper(dt.BoardConfig), i.Plists.BuildManifest.ProductBuildVersion))
	}
	return folders
}

// GetFolderForFile returns a list of the IPSW name folders for a given file
func (i *Info) GetFolderForFile(fileName string) string {
	files := i.getManifestPaths()
	for _, dtree := range i.DeviceTrees {
		dt, _ := dtree.Summary()
		for _, file := range files[strings.ToLower(dt.BoardConfig)] {
			if strings.Contains(fileName, filepath.Base(file)) {
				return fmt.Sprintf("%s_%s_%s", dt.Model, strings.ToUpper(dt.BoardConfig), i.Plists.BuildManifest.ProductBuildVersion)
			}
		}
	}
	return ""
}

func (i *Info) getManifestPaths() map[string][]string {

	files := make(map[string][]string, len(i.Plists.BuildIdentities))

	for _, bID := range i.Plists.BuildIdentities {
		for _, manifest := range bID.Manifest {
			if len(manifest.Info.Path) > 0 {
				files[bID.Info.DeviceClass] = append(files[bID.Info.DeviceClass], manifest.Info.Path)
			}
		}
	}

	return files
}

type folder struct {
	Name         string
	KernelCaches []string
}

func (i *Info) getFolders() []folder {
	var fs []folder
	kcs := i.Plists.BuildManifest.GetKernelCaches()
	for _, dtree := range i.DeviceTrees {
		dt, _ := dtree.Summary()
		fs = append(fs, folder{
			Name:         fmt.Sprintf("%s_%s_%s", dt.Model, strings.ToUpper(dt.BoardConfig), i.Plists.BuildManifest.ProductBuildVersion),
			KernelCaches: kcs[strings.ToLower(dt.BoardConfig)],
		})
	}
	return fs
}

// GetKernelCacheFolders returns the folders belonging to a KernelCache
func (i *Info) GetKernelCacheFolders(kc string) []string {
	var folders []string
	for _, folder := range i.getFolders() {
		for _, kcache := range folder.KernelCaches {
			if strings.HasSuffix(kc, kcache) {
				folders = append(folders, folder.Name)
			}
		}
	}
	return folders
}

// GetKernelCacheFileName returns a short new kernelcache name including all the supported devices
func (i *Info) GetKernelCacheFileName(kc string) string {
	devList := getAbbreviatedDevList(i.GetDevicesForKernelCache(kc))
	return fmt.Sprintf("%s.%s", strings.TrimSuffix(kc, filepath.Ext(kc)), devList)
}

// GetDevicesForKernelCache returns a sorted array of devices that support the kernelcache
func (i *Info) GetDevicesForKernelCache(kc string) []string {
	var devices []string

	for bconf, kcache := range i.Plists.BuildManifest.GetKernelCaches() {
		if utils.StrSliceContains(kcache, kc) {
			for _, dtree := range i.DeviceTrees {
				dt, _ := dtree.Summary()
				if strings.ToLower(bconf) == strings.ToLower(dt.BoardConfig) {
					devices = append(devices, dt.Model)
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

// Parse parses plist files in a local ipsw file
func Parse(ipswPath string) (*Info, error) {
	var err error

	i := &Info{}

	i.Plists, err = plist.Parse(ipswPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse plists")
	}
	i.DeviceTrees, err = devicetree.Parse(ipswPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse devicetree")
	}

	return i, nil
}

// ParseZipFiles parses plist files and devicetree in a remote zip file
func ParseZipFiles(files []*zip.File) (*Info, error) {
	var err error
	i := &Info{}

	i.Plists, err = plist.ParseZipFiles(files)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse remote plists")
	}
	i.DeviceTrees, err = devicetree.ParseZipFiles(files)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse remote devicetree")
	}

	return i, nil
}
