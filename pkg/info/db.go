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

type Intro struct {
	Date    string `json:"date,omitempty"`
	Version string `json:"first_version,omitempty"`
	Build   string `json:"first_build,omitempty"`
}

type Device struct {
	Name       string  `json:"name,omitempty"`
	Boards     []Board `json:"boards,omitempty"`
	MemClass   int     `json:"mem_class,omitempty"`
	Introduced Intro   `json:"introduced,omitempty"`
}

type Devices map[string]Device

func (i *Info) GetDevices(devs *Devices) error {
	var xdev xcode.Device
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
		} else if len(prodName) == 0 {
			prodName = dt.Model
		}

		if i.Plists.Restore != nil { // IPSW
			for _, board := range i.Plists.Restore.DeviceMap {
				if board.BoardConfig == strings.ToLower(dt.BoardConfig) {
					if _, ok := (*devs)[dt.Model]; !ok {
						proc := getProcessor(board.Platform)
						(*devs)[dt.Model] = Device{
							Name: prodName,
							Boards: []Board{
								{
									CPU:         proc.Name,
									Platform:    board.Platform,
									CpuID:       board.CPID,
									CpuISA:      proc.CPUISA,
									Arch:        xdev.DeviceTrait.PreferredArchitecture,
									BoardConfig: dt.BoardConfig,
									BoardID:     board.BDID,
								},
							},
							MemClass:   xdev.DeviceTrait.DevicePerformanceMemoryClass,
							Introduced: Intro{},
						}
					}
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
							MemClass:   xdev.DeviceTrait.DevicePerformanceMemoryClass,
							Introduced: Intro{},
						}
					}
				}
			}
		}
	}

	return nil
}
