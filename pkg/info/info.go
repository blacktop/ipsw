//go:generate statik -src=./data -dest=../../internal

package info

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"github.com/blacktop/ipsw/pkg/devicetree"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/blacktop/ipsw/pkg/xcode"
	"github.com/rakyll/statik/fs"

	// importing statik data
	_ "github.com/blacktop/ipsw/internal/statik"
	"github.com/pkg/errors"
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

	statikFS, err := fs.New()
	if err != nil {
		log.Fatal(err)
	}
	procs, err := statikFS.Open("/procs.json")
	if err != nil {
		log.Fatal(err)
	}

	data, err := ioutil.ReadAll(procs)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(data, &ps)
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

	statikFS, err := fs.New()
	if err != nil {
		log.Fatal(err)
	}
	keysJSON, err := statikFS.Open("/firmware_keys.json")
	if err != nil {
		log.Fatal(err)
	}

	data, err := ioutil.ReadAll(keysJSON)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(data, &keys)
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
