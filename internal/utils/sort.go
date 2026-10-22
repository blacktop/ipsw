package utils

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
)

// Device is an Apple device
type Device struct {
	Family string
	Major  int
	Minor  int
	// Variant is the optional trailing variant of a product type (the "-A" of
	// "iPad16,4-A") that Apple uses to distinguish otherwise identical models.
	Variant string
}

func (d Device) String() string {
	return fmt.Sprintf("%s%d,%d%s", d.Family, d.Major, d.Minor, d.Variant)
}

type Devices []Device

func (d Devices) Len() int      { return len(d) }
func (d Devices) Swap(i, j int) { d[i], d[j] = d[j], d[i] }
func (d Devices) Less(i, j int) bool {
	return fmt.Sprintf("%s%02d%02d%s", d[i].Family, d[i].Major, d[i].Minor, d[i].Variant) < fmt.Sprintf("%s%02d%02d%s", d[j].Family, d[j].Major, d[j].Minor, d[j].Variant)
}

func DeconstructDevice(deviceName string) Device {
	d := Device{}
	re := regexp.MustCompile(`^(?P<family>[a-zA-Z]+)(?P<major>[0-9]+),(?P<minor>[0-9]+)(?P<variant>-[a-zA-Z0-9]+)?$`)
	if re.MatchString(deviceName) {
		matches := re.FindStringSubmatch(deviceName)
		d.Family = matches[re.SubexpIndex("family")]
		i, _ := strconv.Atoi(matches[re.SubexpIndex("major")])
		d.Major = i
		i, _ = strconv.Atoi(matches[re.SubexpIndex("minor")])
		d.Minor = i
		d.Variant = matches[re.SubexpIndex("variant")]
		return d
	}

	return Device{}
}

// SortDevices sorts a list of device names
func SortDevices(devices []string) []string {
	var devs Devices
	var sorted []string
	for _, dev := range devices {
		devs = append(devs, DeconstructDevice(dev))
	}
	sort.Sort(devs)
	for _, dev := range devs {
		sorted = append(sorted, dev.String())
	}
	return sorted
}

func SortFileNameAscend(files []os.FileInfo) {
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() < files[j].Name()
	})
}

func SortFileNameDescend(files []os.FileInfo) {
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() > files[j].Name()
	})
}

func SearchFileName(name string, files []os.FileInfo) (os.FileInfo, error) {
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() < files[j].Name()
	})
	idx := sort.Search(len(files), func(idx int) bool { return files[idx].Name() >= name })
	if idx < len(files) && files[idx].Name() == name {
		return files[idx], nil
	}
	return nil, fmt.Errorf("file %s not found", name)
}
