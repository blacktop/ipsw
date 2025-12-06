package info

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/ota/types"
	"github.com/blacktop/ipsw/pkg/xcode"
)

//go:embed data/ipsw_db.gz
var ipswDbData []byte

type Board struct {
	CPU               string `json:"cpu,omitempty"`
	Platform          string `json:"platform,omitempty"`
	PlatformName      string `json:"platform_name,omitempty"`
	ChipID            string `json:"cpuid,omitempty"`
	Arch              string `json:"arch,omitempty"`
	CpuISA            string `json:"cpuisa,omitempty"`
	BoardID           string `json:"board_id,omitempty"`
	BasebandChipID    string `json:"bbid,omitempty"`
	KernelCacheType   string `json:"kc_type,omitempty"`
	ResearchSupported bool   `json:"research_support,omitempty"`
}

type Device struct {
	Name        string           `json:"name,omitempty"`
	Product     string           `json:"product,omitempty"`
	Description string           `json:"desc,omitempty"`
	Boards      map[string]Board `json:"boards,omitempty"`
	MemClass    uint64           `json:"mem_class,omitempty"`
	SDKPlatform string           `json:"sdk,omitempty"`
	Type        string           `json:"type,omitempty"`
}

type Devices map[string]Device

var colorName = colors.Bold().SprintFunc()
var colorBoard = colors.BoldHiMagenta().SprintFunc()
var colorField = colors.BoldHiBlue().SprintFunc()

func (d Device) String() string {
	var sb strings.Builder
	sb.WriteString("\n" + colorName(d.Name) + "\n")
	if len(d.Description) > 0 {
		sb.WriteString(fmt.Sprintf("  %s: %s\n", colorField("Description"), d.Description))
	}
	if len(d.Product) > 0 {
		sb.WriteString(fmt.Sprintf("  %s: %s\n", colorField("Prod"), d.Product))
	}
	sb.WriteString(fmt.Sprintf("  %s: %s\n", colorField("Type"), d.Type))
	sb.WriteString(fmt.Sprintf("  %s:  %s\n", colorField("SDK"), d.SDKPlatform))
	sb.WriteString(fmt.Sprintf("  %s: %d\n", colorField("Memory Class"), d.MemClass))
	sb.WriteString(fmt.Sprintf("  %s:\n", colorField("Boards")))
	for board, b := range d.Boards {
		sb.WriteString(fmt.Sprintf("    %s:\n", colorBoard(board)))
		sb.WriteString(fmt.Sprintf("      %s:           %s\n", colorField("CPU"), b.CPU))
		sb.WriteString(fmt.Sprintf("      %s:       %s\n", colorField("CPU ISA"), b.CpuISA))
		sb.WriteString(fmt.Sprintf("      %s:       %s\n", colorField("Chip ID"), b.ChipID))
		sb.WriteString(fmt.Sprintf("      %s:      %s\n", colorField("Platform"), b.Platform))
		sb.WriteString(fmt.Sprintf("      %s: %s\n", colorField("Platform Name"), b.PlatformName))
		sb.WriteString(fmt.Sprintf("      %s:          %s\n", colorField("Arch"), b.Arch))
		sb.WriteString(fmt.Sprintf("      %s:      %s\n", colorField("Board ID"), b.BoardID))
		sb.WriteString(fmt.Sprintf("      %s:  %s\n", colorField("Baseband Chip ID"), b.BasebandChipID))
		sb.WriteString(fmt.Sprintf("      %s: %s\n", colorField("Kernel Cache Type"), b.KernelCacheType))
		if b.ResearchSupported {
			sb.WriteString(fmt.Sprintf("      %s: %t\n", colorField("Research Supported"), b.ResearchSupported))
		}
	}
	return sb.String()
}

type DeviceQuery struct {
	Name     string
	Prod     string
	Model    string
	Board    string
	CPU      string
	Platform string
	CPID     string
	BDID     string
}

func GetIpswDB() (*Devices, error) {
	var db Devices

	zr, err := gzip.NewReader(bytes.NewReader(ipswDbData))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	if err := json.NewDecoder(zr).Decode(&db); err != nil {
		return nil, fmt.Errorf("failed unmarshaling ipsw_db data: %w", err)
	}

	return &db, nil
}

func (ds Devices) Query(q *DeviceQuery) *Devices {
	db := make(Devices)
	for prod, dev := range ds {
		dev.Product = prod
		if strings.EqualFold(dev.Name, "iFPGA") ||
			strings.HasSuffix(strings.ToLower(dev.Name), "sim") ||
			strings.HasSuffix(strings.ToLower(dev.Name), "xxx") ||
			strings.HasSuffix(strings.ToLower(dev.Name), "ref") {
			continue
		}
		if len(dev.Type) == 0 || strings.EqualFold(dev.Type, "unknown") {
			continue
		}
		// Name
		if len(q.Name) > 0 {
			// Try regex matching first
			if re, err := regexp.Compile("(?i)" + q.Name); err == nil {
				if re.MatchString(dev.Name) || re.MatchString(dev.Description) {
					db[prod] = dev
					goto next
				}
			} else {
				// Fallback to exact matching if regex is invalid
				if strings.EqualFold(dev.Name, q.Name) || strings.EqualFold(dev.Description, q.Name) {
					db[prod] = dev
					goto next
				}
			}
		}
		// Prod
		if len(q.Prod) > 0 {
			if re, err := regexp.Compile("(?i)" + q.Prod); err == nil {
				if re.MatchString(prod) {
					db[prod] = dev
					goto next
				}
			} else {
				if strings.EqualFold(prod, q.Prod) {
					db[prod] = dev
					goto next
				}
			}
		}
		// Model
		if len(q.Model) > 0 {
			if re, err := regexp.Compile("(?i)" + q.Model); err == nil {
				for m := range dev.Boards {
					if re.MatchString(m) {
						db[prod] = dev
						goto next
					}
				}
			} else {
				for m := range dev.Boards {
					if strings.EqualFold(m, q.Model) {
						db[prod] = dev
						goto next
					}
				}
			}
		}
		// Board
		if len(q.Board) > 0 {
			if re, err := regexp.Compile("(?i)" + q.Board); err == nil {
				for id := range dev.Boards {
					if re.MatchString(id) {
						db[prod] = dev
						goto next
					}
				}
			} else {
				for id := range dev.Boards {
					if strings.EqualFold(id, q.Board) {
						db[prod] = dev
						goto next
					}
				}
			}
		}
		// CPU
		if len(q.CPU) > 0 {
			if re, err := regexp.Compile("(?i)" + q.CPU); err == nil {
				for _, b := range dev.Boards {
					if re.MatchString(b.CPU) {
						db[prod] = dev
						goto next
					}
				}
			} else {
				for _, b := range dev.Boards {
					if strings.EqualFold(b.CPU, q.CPU) {
						db[prod] = dev
						goto next
					}
				}
			}
		}
		// Platform
		if len(q.Platform) > 0 {
			if re, err := regexp.Compile("(?i)" + q.Platform); err == nil {
				for _, b := range dev.Boards {
					if re.MatchString(b.Platform) {
						db[prod] = dev
						goto next
					}
				}
			} else {
				for _, b := range dev.Boards {
					if strings.EqualFold(b.Platform, q.Platform) {
						db[prod] = dev
						goto next
					}
				}
			}
		}
		// CPID
		if len(q.CPID) > 0 {
			if re, err := regexp.Compile("(?i)" + q.CPID); err == nil {
				for _, b := range dev.Boards {
					if re.MatchString(b.ChipID) {
						db[prod] = dev
						goto next
					}
				}
			} else {
				for _, b := range dev.Boards {
					if strings.EqualFold(b.ChipID, q.CPID) {
						db[prod] = dev
						goto next
					}
				}
			}
		}
		// BDID
		if len(q.BDID) > 0 {
			if re, err := regexp.Compile("(?i)" + q.BDID); err == nil {
				for _, b := range dev.Boards {
					if re.MatchString(b.BoardID) {
						db[prod] = dev
						goto next
					}
				}
			} else {
				for _, b := range dev.Boards {
					if strings.EqualFold(b.BoardID, q.BDID) {
						db[prod] = dev
						goto next
					}
				}
			}
		}
	next:
	}
	return &db
}

func (ds Devices) LookupDevice(prod string) (Device, error) {
	if d, ok := ds[prod]; ok {
		return d, nil
	}
	return Device{}, fmt.Errorf("device %s not found", prod)
}

func (ds Devices) GetProductForModel(model string) (string, error) {
	for prod, dev := range ds {
		for m := range dev.Boards {
			if strings.EqualFold(m, model) {
				return prod, nil
			}
		}
	}
	return "", fmt.Errorf("model %s not found", model)
}

func (ds Devices) GetDevicesForType(typ string) (*Devices, error) {
	devs := make(Devices)
	for prod, dev := range ds {
		if dev.Type == typ {
			devs[prod] = dev
		}
	}
	return &devs, nil
}

func (ds Devices) GetDeviceForName(name string) (string, Device, error) {
	for prod, dev := range ds {
		if strings.EqualFold(dev.Name, name) || strings.EqualFold(dev.Description, name) {
			return prod, dev, nil
		}
	}
	return "", Device{}, fmt.Errorf("device not found with name %s", name)
}

func (ds Devices) GetDevicesForSDK(sdk string) (*Devices, error) {
	devs := make(Devices)
	for prod, dev := range ds {
		if dev.SDKPlatform == sdk {
			devs[prod] = dev
		}
	}
	return &devs, nil
}

func (i *Info) GetDevices(devs *Devices) error {
	if len(i.DeviceTrees) > 0 {
		for _, dtree := range i.DeviceTrees {
			dt, err := dtree.Summary()
			if err != nil {
				return fmt.Errorf("error getting device tree summary: %v", err)
			}

			var kctype string
			if kcs := i.Plists.BuildManifest.GetKernelForModel(strings.ToLower(dt.BoardConfig)); kcs != nil {
				if len(kcs) == 1 {
					kctype = kcs[0][strings.LastIndex(kcs[0], ".")+1:]
				} else {
					kctype = kcs[0][strings.LastIndex(kcs[0], ".")+1:] // FIXME: what?
				}
			}

			xdev, err := xcode.GetDeviceForProd(dt.ProductType)
			if err != nil {
				xdev = &xcode.Device{}
				log.Errorf("error getting device %s in xcode device list: %v", dt.ProductType, err)
				// return fmt.Errorf("error getting device %s in xcode device list: %v", dt.ProductType, err)
			}

			devType := "unknown"
			devSDK := "unknown"
			switch {
			case strings.HasPrefix(dt.ProductType, "iPod"):
				fallthrough
			case strings.HasPrefix(dt.ProductType, "iPad"):
				fallthrough
			case strings.HasPrefix(dt.ProductType, "iPhone"):
				devType = "ios"
				devSDK = "iphoneos"
			case strings.HasPrefix(dt.ProductType, "Watch"):
				devType = "watchos"
				devSDK = "watchos"
			case strings.HasPrefix(dt.ProductType, "AudioAccessory"):
				devType = "audioos"
				devSDK = "appletvos"
			case strings.HasPrefix(dt.ProductType, "AppleTV"):
				devType = "tvos"
				devSDK = "appletvos"
			case strings.HasPrefix(dt.ProductType, "Mac"):
				devType = "macos"
				devSDK = "macosx"
			case strings.HasPrefix(dt.ProductType, "AppleDisplay"):
				devType = "accessory"
				devSDK = "iphoneos"
			}

			if len(dt.ProductType) > 0 {
				if _, ok := (*devs)[dt.ProductType]; !ok {
					if dt.ProductName != dt.ProductDescription {
						(*devs)[dt.ProductType] = Device{
							Name:        dt.ProductName,
							Description: dt.ProductDescription,
							Boards:      make(map[string]Board),
							MemClass:    uint64(xdev.DeviceTrait.DevicePerformanceMemoryClass),
							Type:        devType,
							SDKPlatform: devSDK,
						}
					} else {
						(*devs)[dt.ProductType] = Device{
							Name:        dt.ProductName,
							Boards:      make(map[string]Board),
							MemClass:    uint64(xdev.DeviceTrait.DevicePerformanceMemoryClass),
							Type:        devType,
							SDKPlatform: devSDK,
						}
					}
				}
			}

			if i.Plists.Restore != nil && i.Plists.BuildManifest != nil {
				if dev := i.Plists.GetDeviceForBoardConfig(dt.BoardConfig); dev != nil {
					proc, err := getProcessor(dev.Platform)
					if err != nil {
						return fmt.Errorf("failed to get processor for CPU ID %s: %v", dt.DeviceType, err)
					}
					if len(proc.Name) == 0 {
						log.Errorf("no processor for %s for board %s: %s", dt.ProductType, dt.BoardConfig, dt.ProductName)
					}
					(*devs)[dt.ProductType].Boards[dt.BoardConfig] = Board{
						CPU:             proc.Name,
						Platform:        dev.Platform,
						PlatformName:    dt.SocGeneration,
						ChipID:          fmt.Sprintf("%#x", dev.CPID),
						CpuISA:          proc.CPUISA,
						Arch:            xdev.DeviceTrait.PreferredArchitecture,
						BoardID:         fmt.Sprintf("%#x", dev.BDID),
						BasebandChipID:  i.Plists.BuildManifest.BuildIdentities[0].BbChipID,
						KernelCacheType: kctype,
						// ResearchSupported: d.ResearchSupported,
					}
				}
			} else {
				return fmt.Errorf("no restore/BuildManifest plist found for %s", dt.ProductType)
			}
		}
	} else {
		if i.Plists.Restore != nil {
			var prodType string
			var prodName string
			var arch string
			var memClass uint64
			if len(i.Plists.Restore.SupportedProductTypes) == 1 {
				prodType = i.Plists.Restore.SupportedProductTypes[0]
			} else {
				prodType = i.Plists.Restore.SupportedProductTypes[0]
				log.Error("BAD ASSUMPTIONS: multiple product types in restore plist")
			}
			kcs := i.Plists.BuildManifest.GetKernelCaches()
			for _, dev := range i.Plists.Restore.DeviceMap {
				if xdev, err := xcode.GetDeviceForProd(prodType); err == nil {
					prodName = xdev.ProductDescription
					arch = xdev.DeviceTrait.PreferredArchitecture
					memClass = uint64(xdev.DeviceTrait.DevicePerformanceMemoryClass)
				}
				if len(prodName) == 0 {
					if i.Plists.OTAInfo != nil {
						prodName = "FIXME - " + i.Plists.OTAInfo.MobileAssetProperties.DeviceName
					} else {
						prodName = "FIXME"
					}
				}
				if _, ok := (*devs)[prodType]; !ok {
					proc, err := getProcessor(dev.Platform)
					if err != nil {
						return fmt.Errorf("failed to get processor for CPU ID %s: %v", dev.Platform, err)
					}
					if len(proc.Name) == 0 {
						log.Errorf("no processor for %s for board %s: %s", dev.Platform, dev.BoardConfig, prodName)
					}
					(*devs)[prodType] = Device{
						Name: prodName,
						Boards: map[string]Board{
							strings.ToUpper(dev.BoardConfig): {
								CPU:      proc.Name,
								Platform: dev.Platform,
								// PlatformName:      d.PlatformName,
								ChipID:          i.Plists.BuildManifest.BuildIdentities[0].ApChipID,
								CpuISA:          proc.CPUISA,
								Arch:            arch,
								BoardID:         i.Plists.BuildManifest.BuildIdentities[0].ApBoardID,
								BasebandChipID:  i.Plists.BuildManifest.BuildIdentities[0].BbChipID,
								KernelCacheType: kcs[dev.BoardConfig][0][strings.LastIndex(kcs[dev.BoardConfig][0], ".")+1:],
								// ResearchSupported: d.ResearchSupported,
							},
						},
						MemClass: memClass,
					}
				}
			}
		} else {
			panic("unsupported IPSW/OTA type")
		}
	}

	return nil
}

func mLBTypeToBoardConfig(bc string, mlbType string) string {
	return mlbType + strings.ToUpper(strings.TrimPrefix(bc, strings.ToLower(mlbType)))
}

func (i *Info) GetDevicesFromMap(dmap *types.DeviceMap, devs *Devices) error {
	for bc, d := range *dmap {
		if len(d.ProductType) > 0 {
			if _, ok := (*devs)[d.ProductType]; !ok {
				var err error
				var memClass uint64
				if len(d.DevicePerformanceMemoryClass) > 0 {
					memClass, err = utils.ConvertStrToInt(d.DevicePerformanceMemoryClass)
					if err != nil {
						return fmt.Errorf("failed to parse int: %v", err)
					}
				}
				devType := "unknown"
				switch {
				case strings.HasPrefix(d.ProductType, "iPod"):
					fallthrough
				case strings.HasPrefix(d.ProductType, "iPad"):
					fallthrough
				case strings.HasPrefix(d.ProductType, "iPhone"):
					devType = "ios"
				case strings.HasPrefix(d.ProductType, "Watch"):
					devType = "watchos"
				case strings.HasPrefix(d.ProductType, "AudioAccessory"):
					devType = "audioos"
				case strings.HasPrefix(d.ProductType, "AppleTV") || d.SDKPlatform == "appletvos":
					devType = "tvos"
				case strings.HasPrefix(d.ProductType, "Mac") || d.SDKPlatform == "macosx":
					devType = "macos"
				case strings.HasPrefix(d.ProductType, "AppleDisplay"):
					devType = "accessory"
				}
				if d.ProductName != d.ProductDescription {
					(*devs)[d.ProductType] = Device{
						Name:        d.ProductName,
						Description: d.ProductDescription,
						Boards:      make(map[string]Board),
						MemClass:    memClass,
						SDKPlatform: d.SDKPlatform,
						Type:        devType,
					}
				} else {
					(*devs)[d.ProductType] = Device{
						Name:        d.ProductName,
						Boards:      make(map[string]Board),
						MemClass:    memClass,
						SDKPlatform: d.SDKPlatform,
						Type:        devType,
					}
				}
			}
			proc, err := getProcessor(d.Platform)
			if err != nil {
				return fmt.Errorf("failed to get processor for CPU ID %s: %v", d.Platform, err)
			}
			if len(proc.Name) == 0 {
				log.Errorf("no processor for %s for board %s: %s", d.Platform, bc, d.ProductName)
			}
			(*devs)[d.ProductType].Boards[mLBTypeToBoardConfig(bc, d.MLBType)] = Board{
				CPU:               proc.Name,
				Platform:          d.Platform,
				PlatformName:      d.PlatformName,
				ChipID:            d.ChipID,
				CpuISA:            proc.CPUISA,
				Arch:              d.KernelMachOArchitecture,
				BoardID:           d.BoardID,
				BasebandChipID:    d.BasebandChipID,
				KernelCacheType:   d.KernelCacheType,
				ResearchSupported: d.ResearchSupported,
			}
		} else {
			log.Debugf("Board %s has no product type", bc)
		}
	}

	return nil
}
