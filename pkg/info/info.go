//go:generate statik -src=./data -dest=../..

package info

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"github.com/blacktop/ipsw/pkg/devicetree"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/rakyll/statik/fs"

	// importing statik data
	_ "github.com/blacktop/ipsw/statik"
	"github.com/pkg/errors"
)

// IPSW in the ipsw info object
type IPSW struct {
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

func (i *IPSW) String() string {
	var iStr string
	iStr += fmt.Sprintf(
		"\n[IPSW Info]\n"+
			"===========\n"+
			"Version        = %s\n"+
			"BuildVersion   = %s\n"+
			"OS Type        = %s\n",
		i.Plists.BuildManifest.ProductVersion,
		i.Plists.BuildManifest.ProductBuildVersion,
		i.Plists.BuildManifest.GetOSType(),
	)
	iStr += fmt.Sprintf("FileSystem     = ")
	for file, fsType := range i.Plists.Restore.SystemRestoreImageFileSystems {
		iStr += fmt.Sprintf("%s (Type: %s)\n", file, fsType)
	}
	kcs := i.Plists.BuildManifest.GetKernelCaches()
	iStr += fmt.Sprintf("\nDevices\n")
	iStr += fmt.Sprintf("-------\n")
	for _, dtree := range i.DeviceTrees {
		dt, _ := dtree.Summary()
		iStr += fmt.Sprintf("\n%s)\n", dt.ProductName)
		iStr += fmt.Sprintf(" - %s_%s_%s\n", dt.Model, strings.ToUpper(dt.BoardConfig), i.Plists.Restore.ProductBuildVersion)
		iStr += fmt.Sprintf("   - KernelCache: %s\n", kcs[strings.ToLower(dt.BoardConfig)])
		for _, device := range i.Plists.Restore.DeviceMap {
			if strings.ToLower(device.BoardConfig) == strings.ToLower(dt.BoardConfig) {
				proc := getProcessor(device.Platform)
				iStr += fmt.Sprintf("   - CPU: %s (%s), ID: %s\n", proc.Name, proc.CPUISA, device.Platform)
			}
		}
	}
	return iStr
}

type folder struct {
	Name        string
	KernelCache string
}

func (i *IPSW) getFolders() []folder {
	var fs []folder
	kcs := i.Plists.BuildManifest.GetKernelCaches()
	for _, dtree := range i.DeviceTrees {
		dt, _ := dtree.Summary()
		fs = append(fs, folder{
			Name:        fmt.Sprintf("%s_%s_%s", dt.Model, strings.ToUpper(dt.BoardConfig), i.Plists.Restore.ProductBuildVersion),
			KernelCache: kcs[strings.ToLower(dt.BoardConfig)],
		})
	}
	return fs
}

// GetFolders returns a list of the IPSW name folders
func (i *IPSW) GetFolders() []string {
	var folders []string
	for _, dtree := range i.DeviceTrees {
		dt, _ := dtree.Summary()
		folders = append(folders, fmt.Sprintf("%s_%s_%s", dt.Model, strings.ToUpper(dt.BoardConfig), i.Plists.Restore.ProductBuildVersion))

	}
	return folders
}

func (i *IPSW) GetFolderForFile(fileName string) string {
	files := i.getManifestPaths()
	for _, dtree := range i.DeviceTrees {
		dt, _ := dtree.Summary()
		for _, file := range files[strings.ToLower(dt.BoardConfig)] {
			if strings.Contains(fileName, filepath.Base(file)) {
				return fmt.Sprintf("%s_%s_%s", dt.Model, strings.ToUpper(dt.BoardConfig), i.Plists.Restore.ProductBuildVersion)
			}
		}
	}
	return ""
}

func (i *IPSW) getManifestPaths() map[string][]string {

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

// GetKernelCacheFolders returns the folders belonging to a KernelCache
func (i *IPSW) GetKernelCacheFolders(kc string) []string {
	var folders []string
	for _, folder := range i.getFolders() {
		if strings.EqualFold(folder.KernelCache, kc) {
			folders = append(folders, folder.Name)
		}
	}
	return folders
}

// Parse parses plist files in a local ipsw file
func Parse(ipswPath string) (*IPSW, error) {
	var err error

	ipsw := &IPSW{}

	ipsw.Plists, err = plist.Parse(ipswPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse plists")
	}
	ipsw.DeviceTrees, err = devicetree.Parse(ipswPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse devicetree")
	}

	return ipsw, nil
}

// RemoteParse parses plist files in a remote ipsw file
func RemoteParse(url string) (*IPSW, error) {
	var err error

	ipsw := &IPSW{}

	ipsw.Plists, err = plist.RemoteParse(url)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse plists")
	}
	ipsw.DeviceTrees, err = devicetree.RemoteParse(url)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse devicetree")
	}

	return ipsw, nil
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
