package utils

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

func PickDevices() ([]*lockdownd.DeviceValues, error) {
	var deets []*lockdownd.DeviceValues

	conn, err := usb.NewConn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	devices, err := conn.ListDevices()
	if err != nil {
		return nil, err
	}

	for _, device := range devices {
		ldc, err := lockdownd.NewClient(device.UDID)
		if err != nil {
			return nil, err
		}
		defer ldc.Close()

		deet, err := ldc.GetValues()
		if err != nil {
			return nil, err
		}

		deets = append(deets, deet)
	}

	if len(deets) == 1 {
		return deets, nil
	} else {
		var choices []string
		for _, d := range deets {
			choices = append(choices, fmt.Sprintf("%s_%s_%s", d.ProductType, d.HardwareModel, d.BuildVersion))
		}
		selected := []int{}
		prompt := &survey.MultiSelect{
			Message: "Select what iDevice's IPSW to download:",
			Options: choices,
		}
		if err := survey.AskOne(prompt, &selected); err == terminal.InterruptErr {
			log.Warn("Exiting...")
			os.Exit(0)
		}
		// filter based on selection
		var picked []*lockdownd.DeviceValues
		for _, idx := range selected {
			picked = append(picked, deets[idx])
		}

		return picked, nil
	}
}
