package utils

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
)

// Device is an Apple device
type Device struct {
	Family string
	Major  int
	Minor  int
}

func (d Device) String() string {
	return fmt.Sprintf("%s%d,%d", d.Family, d.Major, d.Minor)
}

type Devices []Device

func (d Devices) Len() int      { return len(d) }
func (d Devices) Swap(i, j int) { d[i], d[j] = d[j], d[i] }
func (d Devices) Less(i, j int) bool {
	return fmt.Sprintf("%s%02d%02d", d[i].Family, d[i].Major, d[i].Minor) < fmt.Sprintf("%s%02d%02d", d[j].Family, d[j].Major, d[j].Minor)
}

func DeconstructDevice(deviceName string) Device {
	d := Device{}
	re := regexp.MustCompile(`^(?P<family>[a-zA-Z]+)(?P<major>[0-9]+),(?P<minor>[0-9]+)$`)
	if re.MatchString(deviceName) {
		matches := re.FindStringSubmatch(deviceName)
		d.Family = matches[re.SubexpIndex("family")]
		i, _ := strconv.Atoi(matches[re.SubexpIndex("major")])
		d.Major = i
		i, _ = strconv.Atoi(matches[re.SubexpIndex("minor")])
		d.Minor = i
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
