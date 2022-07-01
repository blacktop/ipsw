package utils

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/blacktop/go-plist"
)

// Cp copies a file from src to dest
func Cp(src, dst string) error {
	from, err := os.Open(src)
	if err != nil {
		return err
	}
	defer from.Close()

	to, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE, 0660)
	if err != nil {
		return err
	}
	defer to.Close()

	_, err = io.Copy(to, from)

	return err
}

// CodeSign codesigns a given binary
func CodeSign(filePath, signature string) error {
	if runtime.GOOS == "darwin" {
		filePath = filepath.Clean(filePath)
		cmd := exec.Command("codesign -s - -f", "-s", signature, "-f", filePath)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}

		return nil
	}

	return fmt.Errorf("only supported on macOS")
}

// CodeSignWithEntitlements codesigns a given binary with given entitlements
func CodeSignWithEntitlements(filePath, entitlementsPath, signature string) error {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("codesign", "--entitlements", entitlementsPath, "-s", signature, "-f", filepath.Clean(filePath))
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}

		return nil
	}

	return fmt.Errorf("only supported on macOS")
}

// CodeSignAdHoc codesigns a given binary with ad-hoc signature
func CodeSignAdHoc(filePath string) error {
	return CodeSign(filePath, "-")
}

// CreateSparseDiskImage creates a sparse disk image and returns it's path
func CreateSparseDiskImage(volumeName, diskPath string) (string, error) {
	if runtime.GOOS == "darwin" {

		cmd := exec.Command("hdiutil", "create", "-size", "16g", "-fs", "HFS+", "-volname", volumeName, "-type", "SPARSE", "-plist", diskPath)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%v: %s", err, out)
		}

		var paths []string
		if err := plist.NewDecoder(bytes.NewReader(out)).Decode(&paths); err != nil {
			return "", fmt.Errorf("failed to parse hdiutil output plist: %v", err)
		}

		return paths[0], nil
	}

	return "", fmt.Errorf("only supported on macOS")
}

// CreateCompressedDMG creates a compressed r/o disk image containing Install macOS.app
func CreateCompressedDMG(appPath, diskimagePath string) error {
	if runtime.GOOS == "darwin" {

		cmd := exec.Command("/usr/bin/hdiutil", "create", "-fs", "HFS+", "-srcfolder", appPath, diskimagePath)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}

		return nil
	}

	return fmt.Errorf("only supported on macOS")
}

// CreateInstaller creates an macOS installer
func CreateInstaller(distPath, targetVol string) error {
	if runtime.GOOS == "darwin" {

		cmd := exec.Command("/usr/sbin/installer", "-pkg", distPath, "-target", targetVol)
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, "CM_BUILD=CM_BUILD")

		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}

		if _, err := os.Stat(targetVol + "Applications"); os.IsNotExist(err) {
			cmd := exec.Command("/usr/bin/ditto", targetVol+"Applications", filepath.Join(targetVol, "Applications"))
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("%v: %s", err, out)
			}

			cmd = exec.Command("/bin/rm", "-r", targetVol+"Applications")
			out, err = cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("%v: %s", err, out)
			}
		}

		return nil
	}

	return fmt.Errorf("only supported on macOS")
}

type IORegistryEntryChild struct {
	IOBusyInterest              string
	IOConsoleSecurityInterest   string
	IOInterruptControllers      []string
	IOInterruptSpecifiers       [][]byte
	IOObjectClass               string
	IOObjectRetainCount         int
	IOPlatformSerialNumber      string
	IOPlatformSystemSleepPolicy []byte
	IOPlatformUUID              string
	IOPolledInterface           string
	IORegistryEntryID           int
	IORegistryEntryName         string
	IOServiceBusyState          int
	IOServiceBusyTime           int
	IOServiceState              int
	BoardID                     []byte `plist:"board-id,omitempty"`
	BridgeModel                 []byte `plist:"bridge-model,omitempty"`
	ClockFrequency              []byte `plist:"clock-frequency,omitempty"`
	Compatible                  []byte `plist:"compatible,omitempty"`
	Manufacturer                []byte `plist:"manufacturer,omitempty"`
	Model                       []byte `plist:"model,omitempty"`
	Name                        []byte `plist:"name,omitempty"`
	PlatformFeature             []byte `plist:"platform-feature,omitempty"`
	ProductName                 []byte `plist:"product-name,omitempty"`
	SerialNumber                []byte `plist:"serial-number,omitempty"`
	SystemType                  []byte `plist:"system-type,omitempty"`
	TargetType                  []byte `plist:"target-type,omitempty"`
	Version                     []byte `plist:"version,omitempty"`
}

func (e IORegistryEntryChild) String() string {
	return fmt.Sprintf(
		"Name:            %s\n"+
			"Model:           %s\n"+
			"ProductName:     %s\n"+
			"Compatible:      %s\n"+
			"BridgeModel:     %s\n"+
			"BoardID:         %s\n"+
			"TargetType:      %s\n"+
			"SystemType:      %d\n"+
			"PlatformFeature: %s\n"+
			"ClockFrequency:  %#x\n"+
			"Manufacturer:    %s\n"+
			"Version:         %s\n",
		string(e.Name),
		string(e.Model),
		string(e.ProductName),
		string(e.Compatible),
		string(e.BridgeModel),
		string(e.BoardID),
		string(e.TargetType),
		e.SystemType,
		string(e.PlatformFeature),
		binary.BigEndian.Uint32(e.ClockFrequency),
		string(e.Manufacturer),
		string(e.Version),
	)
}

type DeviceID struct {
	IOObjectClass           string
	IOObjectRetainCount     int
	IORegistryEntryChildren []IORegistryEntryChild
	IORegistryEntryID       int
	IORegistryEntryName     string
}

// GetDeviceID returns the ioreg IOPlatformExpertDevice of the current device
func GetDeviceID() (*DeviceID, error) {
	if runtime.GOOS == "darwin" {

		cmd := exec.Command("/usr/sbin/ioreg", "-c", "IOPlatformExpertDevice", "-d", "2", "-a")

		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%v: %s", err, out)
		}

		var dID DeviceID
		if err := plist.NewDecoder(bytes.NewReader(out)).Decode(&dID); err != nil {
			return nil, fmt.Errorf("failed to parse hdiutil output plist: %v", err)
		}

		return &dID, nil
	}
	return nil, fmt.Errorf("only supported on macOS")
}

type BuildInfo struct {
	ProductNames   string
	ProductVersion string
	BuildVersion   string
}

// GetBuildInfo returns the current device OS build info
func GetBuildInfo() (*BuildInfo, error) {
	if runtime.GOOS == "darwin" {
		var binfo BuildInfo

		cmd := exec.Command("/usr/bin/sw_vers", "-productName")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%v: %s", err, out)
		}

		binfo.ProductNames = string(out)

		cmd = exec.Command("/usr/bin/sw_vers", "-productVersion")
		out, err = cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%v: %s", err, out)
		}

		binfo.ProductVersion = string(out)

		cmd = exec.Command("/usr/bin/sw_vers", "-buildVersion")
		out, err = cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%v: %s", err, out)
		}

		binfo.BuildVersion = string(out)

		return &binfo, nil
	}
	return nil, fmt.Errorf("only supported on macOS")
}

// Mount mounts a DMG with hdiutil
func Mount(image, mountPoint string) error {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("hdiutil", "attach", "-noverify", "-mountpoint", mountPoint, image)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}

		return nil

	} else if runtime.GOOS == "linux" {
		cmd := exec.Command("apfs-fuse", image, mountPoint)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}

		return nil
	}

	return nil
}

func MountFS(image string) (string, error) {
	var mountPoint string
	if runtime.GOOS == "darwin" {
		mountPoint = "/tmp/ios"
	} else {
		if _, ok := os.LookupEnv("IPSW_IN_DOCKER"); ok {
			// Create in-docker mount point
			os.MkdirAll("/data", 0750)
			mountPoint = "/mnt"
		} else {
			// Create temporary non-darwin mount point
			mountPoint = image + "_temp_mount"
			if err := os.Mkdir(mountPoint, 0750); err != nil {
				return "", fmt.Errorf("failed to create temporary mount point %s: %v", mountPoint, err)
			}
		}
	}
	if err := Mount(image, mountPoint); err != nil {
		return "", fmt.Errorf("failed to mount %s: %v", image, err)
	}
	return mountPoint, nil
}

// Unmount unmounts a DMG with hdiutil
func Unmount(mountPoint string, force bool) error {
	if runtime.GOOS == "darwin" {
		var cmd *exec.Cmd

		if force {
			cmd = exec.Command("hdiutil", "detach", mountPoint, "-force")
		} else {
			cmd = exec.Command("hdiutil", "detach", mountPoint)
		}

		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to unmount %s: %v", mountPoint, err)
		}

	} else if runtime.GOOS == "linux" {
		cmd := exec.Command("umount", mountPoint)

		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to unmount %s: %v", mountPoint, err)
		}
	}

	return nil
}
