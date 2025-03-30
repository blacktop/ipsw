package utils

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"

	"github.com/blacktop/ipsw/pkg/ddi"
)

const devicectlPath = "/Library/Developer/PrivateFrameworks/CoreDevice.framework/Resources/bin/devicectl"

func PreferredDDI() (*ddi.Info, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("only supported on macOS")
	}
	cmd := exec.Command(devicectlPath, "list", "preferredDDI", "--quiet", "--json-output", "-")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get preferred DDI: %v", err)
	}
	var info ddi.Info
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal preferred DDI: %v", err)
	}
	return &info, nil
}

func UpdateDDIsFromXCode() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("only supported on macOS")
	}
	cmd := exec.Command(devicectlPath, "manage", "ddis", "update", "--no-include-coredevice", "--include-xcode", "--clean")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to update DDIs: %v", err)
	}
	return string(out), nil
}

func UpdateDDIs(sourceDir string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("only supported on macOS")
	}
	cmd := exec.Command(devicectlPath, "manage", "ddis", "update", "--no-include-coredevice", "--no-include-xcode", "--source-dir", sourceDir, "--clean")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to update DDIs: %v", err)
	}
	return string(out), nil
}

func CleanDDIs() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("only supported on macOS")
	}
	cmd := exec.Command(devicectlPath, "manage", "ddis", "clean")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to clean DDIs: %v", err)
	}
	return string(out), nil
}

func ListCrashes(device string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("only supported on macOS")
	}
	cmd := exec.Command(devicectlPath, "device", "info", "files", "--username=mobile", "--domain-type=systemCrashLogs", "--device", device)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to list crashes: %v", err)
	}
	return string(out), nil
}
