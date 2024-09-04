package utils

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/blacktop/ipsw/pkg/usb/mount"
)

func PickDevice() (*lockdownd.DeviceValues, error) {
	var deets []*lockdownd.DeviceValues

	conn, err := usb.NewConn()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to usbmuxd: %w", err)
	}
	defer conn.Close()

	devices, err := conn.ListDevices()
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}

	if len(devices) == 0 {
		return nil, fmt.Errorf("no devices found")
	}

	for _, device := range devices {
		ldc, err := lockdownd.NewClient(device.SerialNumber)
		if err != nil {
			return nil, err
		}

		deet, err := ldc.GetValues()
		if err != nil {
			return nil, err
		}

		deets = append(deets, deet)

		ldc.Close()
	}

	if len(deets) == 1 {
		return deets[0], nil
	}

	selected := make(map[string]*lockdownd.DeviceValues, len(deets))
	for _, d := range deets {
		selected[fmt.Sprintf("%s_%s_%s", d.ProductType, d.HardwareModel, d.BuildVersion)] = d
	}

	if len(selected) == 1 {
		return deets[0], nil // can happen if device setup to connect via network
	}

	var choices []string
	for s := range selected {
		choices = append(choices, s)
	}

	var picked string
	prompt := &survey.Select{
		Message: "Select what iDevice to connect to:",
		Options: choices,
	}
	if err := survey.AskOne(prompt, &picked); err == terminal.InterruptErr {
		log.Warn("Exiting...")
		os.Exit(0)
	}

	return selected[picked], nil
}

func PickDevices() ([]*lockdownd.DeviceValues, error) {
	var deets []*lockdownd.DeviceValues

	conn, err := usb.NewConn()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to usbmuxd: %w", err)
	}
	defer conn.Close()

	devices, err := conn.ListDevices()
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}

	if len(devices) == 0 {
		return nil, fmt.Errorf("no devices found")
	}

	for _, device := range devices {
		ldc, err := lockdownd.NewClient(device.SerialNumber)
		if err != nil {
			return nil, err
		}

		deet, err := ldc.GetValues()
		if err != nil {
			return nil, err
		}

		deets = append(deets, deet)

		ldc.Close()
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
			Message: "Select what iDevices to connect to:",
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

func IsDeveloperModeEnabled(udid string) (bool, error) {
	cli, err := lockdownd.NewClient(udid)
	if err != nil {
		return false, fmt.Errorf("failed to connect to lockdownd: %w", err)
	}
	defer cli.Close()
	return cli.DeveloperModeEnabled()
}

func IsDeveloperImageMounted(udid string) error {
	cli, err := mount.NewClient(udid)
	if err != nil {
		return fmt.Errorf("failed to connect to mobile_image_mounter: %w", err)
	}
	defer cli.Close()

	images, err := cli.ListImages()
	if err != nil {
		return fmt.Errorf("failed to list images: %w", err)
	}

	if len(images) == 0 {
		return fmt.Errorf("mount the Developer image with the `ipsw idev img mount` command or by opening Xcode")
	}

	return nil
}
