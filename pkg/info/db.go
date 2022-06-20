package info

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/apex/log"
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
	Description string           `json:"desc,omitempty"`
	Boards      map[string]Board `json:"boards,omitempty"`
	MemClass    string           `json:"mem_class,omitempty"`
	SDKPlatform string           `json:"sdk,omitempty"`
}

type Devices map[string]Device

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

func (ds Devices) LookupDevice(prod string) (Device, error) {
	if d, ok := ds[prod]; ok {
		return d, nil
	}
	return Device{}, fmt.Errorf("device %s not found", prod)
}

func (i *Info) GetDevices(devs *Devices) error {
	if i.DeviceTrees != nil && len(i.DeviceTrees) > 0 {
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

			if len(dt.ProductType) > 0 {
				if _, ok := (*devs)[dt.ProductType]; !ok {
					if dt.ProductName != dt.ProductDescription {
						(*devs)[dt.ProductType] = Device{
							Name:        dt.ProductName,
							Description: dt.ProductDescription,
							Boards:      make(map[string]Board),
							MemClass:    strconv.Itoa(xdev.DeviceTrait.DevicePerformanceMemoryClass),
						}
					} else {
						(*devs)[dt.ProductType] = Device{
							Name:     dt.ProductName,
							Boards:   make(map[string]Board),
							MemClass: strconv.Itoa(xdev.DeviceTrait.DevicePerformanceMemoryClass),
						}
					}
				}
			}

			proc, err := getProcessor(xdev.Platform)
			if err != nil {
				return fmt.Errorf("failed to get processor for CPU ID %s: %v", xdev.Platform, err)
			}

			if len(proc.Name) == 0 {
				log.Errorf("no processor for %s for board %s: %s", dt.ProductType, dt.BoardConfig, dt.ProductName)
			}

			(*devs)[dt.ProductType].Boards[dt.BoardConfig] = Board{
				CPU:      proc.Name,
				Platform: xdev.Platform,
				// PlatformName:      d.PlatformName,
				ChipID:          i.Plists.BuildManifest.BuildIdentities[0].ApChipID,
				CpuISA:          proc.CPUISA,
				Arch:            xdev.DeviceTrait.PreferredArchitecture,
				BoardID:         i.Plists.BuildManifest.BuildIdentities[0].ApBoardID,
				BasebandChipID:  i.Plists.BuildManifest.BuildIdentities[0].BbChipID,
				KernelCacheType: kctype,
				// ResearchSupported: d.ResearchSupported,
			}
		}
	} else {
		if i.Plists.Restore != nil {
			var prodType string
			var prodName string
			var arch string
			var memClass string
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
					memClass = strconv.Itoa(xdev.DeviceTrait.DevicePerformanceMemoryClass)
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
				if d.ProductName != d.ProductDescription {
					(*devs)[d.ProductType] = Device{
						Name:        d.ProductName,
						Description: d.ProductDescription,
						Boards:      make(map[string]Board),
						MemClass:    d.DevicePerformanceMemoryClass,
						SDKPlatform: d.SDKPlatform,
					}
				} else {
					(*devs)[d.ProductType] = Device{
						Name:        d.ProductName,
						Boards:      make(map[string]Board),
						MemClass:    d.DevicePerformanceMemoryClass,
						SDKPlatform: d.SDKPlatform,
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
