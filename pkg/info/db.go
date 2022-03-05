package info

import (
	"strings"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/xcode"
)

type Board struct {
	CPU         string `json:"cpu,omitempty"`
	Platform    string `json:"platform,omitempty"`
	CpuID       int    `json:"cpu_id,omitempty"`
	Arch        string `json:"arch,omitempty"`
	CpuISA      string `json:"cpu_isa,omitempty"`
	BoardConfig string `json:"board_config,omitempty"`
	BoardID     int    `json:"board_id,omitempty"`
}

type Device struct {
	Name     string  `json:"name,omitempty"`
	Boards   []Board `json:"boards,omitempty"`
	MemClass int     `json:"mem_class,omitempty"`
}

type Devices map[string]Device

func (i *Info) GetDevices(devs *Devices) error {
	var xdev xcode.Device
	if i.DeviceTrees != nil && len(i.DeviceTrees) > 0 {
		for _, dtree := range i.DeviceTrees {
			dt, _ := dtree.Summary()
			prodName := dt.ProductName

			if devices, err := xcode.GetDevices(); err == nil {
				for _, device := range devices {
					if device.ProductType == dt.Model {
						xdev = device
						if len(prodName) == 0 {
							prodName = xdev.ProductDescription
						}
						break
					}
				}
			}

			if i.Plists.Restore != nil { // IPSW
				var boards []Board
				for _, board := range i.Plists.Restore.DeviceMap {
					if board.BoardConfig == strings.ToLower(dt.BoardConfig) {
						proc := getProcessor(board.Platform)
						boards = append(boards, Board{
							CPU:         proc.Name,
							Platform:    board.Platform,
							CpuID:       board.CPID,
							CpuISA:      proc.CPUISA,
							Arch:        xdev.DeviceTrait.PreferredArchitecture,
							BoardConfig: dt.BoardConfig,
							BoardID:     board.BDID,
						})
					}
				}
				if _, ok := (*devs)[dt.Model]; !ok {
					(*devs)[dt.Model] = Device{
						Name:     prodName,
						Boards:   boards,
						MemClass: xdev.DeviceTrait.DevicePerformanceMemoryClass,
					}
				}
			} else { // OTA
				for _, board := range i.Plists.BuildIdentities {
					if board.Info.DeviceClass == strings.ToLower(dt.BoardConfig) {
						if _, ok := (*devs)[dt.Model]; !ok {
							chipID, err := utils.ConvertStrToInt(board.ApChipID)
							if err != nil {
								chipID = 0
							}
							boardID, err := utils.ConvertStrToInt(board.ApBoardID)
							if err != nil {
								boardID = 0
							}
							proc := getProcessor(xdev.Platform)
							(*devs)[dt.Model] = Device{
								Name: prodName,
								Boards: []Board{
									{
										CPU:         proc.Name,
										Platform:    xdev.Platform,
										CpuID:       int(chipID),
										CpuISA:      proc.CPUISA,
										Arch:        xdev.DeviceTrait.PreferredArchitecture,
										BoardConfig: dt.BoardConfig,
										BoardID:     int(boardID),
									},
								},
								MemClass: xdev.DeviceTrait.DevicePerformanceMemoryClass,
							}
						}
					}
				}
			}
		}
	} else {
		if i.Plists.Restore != nil {
			var prodName string
			for idx, prod := range i.Plists.Restore.SupportedProductTypes {
				if devices, err := xcode.GetDevices(); err == nil {
					for _, device := range devices {
						if device.ProductType == prod {
							xdev = device
							if len(prodName) == 0 {
								prodName = xdev.ProductDescription
							}
							break
						}
					}
				} else if len(prodName) == 0 {
					if i.Plists.OTAInfo != nil {
						prodName = "FIXME - " + i.Plists.OTAInfo.MobileAssetProperties.DeviceName
					} else {
						prodName = "FIXME"
					}
				}
				if _, ok := (*devs)[prod]; !ok {
					proc := getProcessor(i.Plists.Restore.DeviceMap[idx].Platform)
					(*devs)[prod] = Device{
						Name: prodName,
						Boards: []Board{
							{
								CPU:         proc.Name,
								Platform:    i.Plists.Restore.DeviceMap[idx].Platform,
								CpuID:       i.Plists.Restore.DeviceMap[idx].CPID,
								CpuISA:      proc.CPUISA,
								Arch:        xdev.DeviceTrait.PreferredArchitecture,
								BoardConfig: strings.ToUpper(i.Plists.Restore.DeviceMap[idx].BoardConfig),
								BoardID:     i.Plists.Restore.DeviceMap[idx].BDID,
							},
						},
						MemClass: xdev.DeviceTrait.DevicePerformanceMemoryClass,
					}
				}
			}
		} else {
			panic("unsupport IPSW/OTA type w/ no devicetree?")
		}
	}

	return nil
}
