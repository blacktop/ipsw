package utils

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/apex/log"
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

// Copy recursively copies src into dst with src's file modes.
// CREDIT: https://github.com/goreleaser/goreleaser/blob/main/internal/gio/copy.go
func Copy(src, dst string) error {
	return CopyWithMode(src, dst, 0)
}

// CopyWithMode recursively copies src into dst with the given mode.
// The given mode applies only to files. Their parent dirs will have the same mode as their src counterparts.
func CopyWithMode(src, dst string, mode os.FileMode) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("failed to copy %s to %s: %w", src, dst, err)
		}
		// We have the following:
		// - src = "a/b"
		// - dst = "dist/linuxamd64/b"
		// - path = "a/b/c.txt"
		// So we join "a/b" with "c.txt" and use it as the destination.
		dst := filepath.Join(dst, strings.Replace(path, src, "", 1))
		if info.IsDir() {
			return os.MkdirAll(dst, info.Mode())
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return copySymlink(path, dst)
		}
		if mode != 0 {
			return copyFile(path, dst, mode)
		}
		return copyFile(path, dst, info.Mode())
	})
}

func copySymlink(src, dst string) error {
	src, err := os.Readlink(src)
	if err != nil {
		return err
	}
	return os.Symlink(src, dst)
}

func copyFile(src, dst string, mode os.FileMode) error {
	original, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open '%s': %w", src, err)
	}
	defer original.Close()

	new, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("failed to open '%s': %w", dst, err)
	}
	defer new.Close()

	if _, err := io.Copy(new, original); err != nil {
		return fmt.Errorf("failed to copy: %w", err)
	}
	return nil
}

// CodeSign codesigns a given binary
func CodeSign(filePath, signature string) error {
	if runtime.GOOS == "darwin" {
		filePath = filepath.Clean(filePath)
		cmd := exec.Command("/usr/bin/codesign", "-s", "-", "-f", "-s", signature, "-f", filePath)

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
		cmd := exec.Command("/usr/bin/codesign", "--entitlements", entitlementsPath, "-s", signature, "-f", filepath.Clean(filePath))
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

func CodesignVerify(path string) (string, error) {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("codesign", "--verify", "--deep", "--strict", "--verbose=4", path)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%v: %s", err, out)
		}
		return string(out), nil
	}
	return "", fmt.Errorf("only supported on macOS")
}

func CodesignShow(path string) (string, error) {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("codesign", "-d", "--verbose=4", path)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%v: %s", err, out)
		}
		return string(out), nil
	}
	return "", fmt.Errorf("only supported on macOS")
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

func GetKernelCollectionPath() (string, error) {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("sysctl", "-n", "kern.bootobjectspath")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "/System/Library/KernelCollections/BootKernelExtensions.kc", nil
		}
		return filepath.Join("/System/Volumes/Preboot", strings.TrimSpace(string(out)), "System/Library/Caches/com.apple.kernelcaches/kernelcache"), nil
	}
	return "", fmt.Errorf("only supported on macOS")
}

var ErrMountResourceBusy = errors.New("hdiutil: mount failed - Resource busy")

// Mount mounts a DMG with hdiutil
func Mount(image, mountPoint string) error {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("/usr/bin/hdiutil", "attach", "-noverify", "-mountpoint", mountPoint, image)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}

		return nil
	}

	if _, err := exec.LookPath("apfs-fuse"); err != nil {
		return fmt.Errorf("utils.Mount: apfs-fuse not found (required on non-darwin systems): %v", err)
	}

	cmd := exec.Command("apfs-fuse", image, mountPoint)

	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "hdiutil: mount failed - Resource busy") {
			return ErrMountResourceBusy
		}
		return fmt.Errorf("%v: %s", err, out)
	}

	return nil
}

func IsAlreadyMounted(image, mountPoint string) (string, bool, error) {
	if runtime.GOOS == "darwin" {
		info, err := MountInfo()
		if err != nil {
			return "", false, err
		}
		for _, i := range info.Images {
			if strings.Contains(i.ImagePath, image) {
				for _, entry := range i.SystemEntities {
					if entry.MountPoint != "" {
						return entry.MountPoint, true, nil
					}
				}
				return "", true, nil
			}
		}
	} else if runtime.GOOS == "linux" {
		if _, err := os.Stat(filepath.Join(mountPoint, "root")); !os.IsNotExist(err) {
			return mountPoint, true, nil
		}
	}
	return "", false, nil
}

func MountFS(image string) (string, bool, error) {
	mountPoint := fmt.Sprintf("/tmp/%s.mount", filepath.Base(image))

	if runtime.GOOS == "darwin" {
		// check if already mounted
		if prevMountPoint, mounted, err := IsAlreadyMounted(image, mountPoint); mounted && err == nil {
			if prevMountPoint != "" {
				mountPoint = prevMountPoint
			}
			return mountPoint, true, nil
		}
	} else {
		if err := os.Mkdir(mountPoint, 0750); err != nil {
			return "", false, fmt.Errorf("failed to create temporary mount point %s: %v", mountPoint, err)
		}
	}

	if err := Mount(image, mountPoint); err != nil {
		return "", false, fmt.Errorf("failed to mount %s: %v", image, err)
	}

	return mountPoint, false, nil
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

		if err := cmd.Run(); err != nil {
			var edetail string
			if strings.Contains(err.Error(), "exit status 16") {
				edetail = " (Resource busy)"
			}
			return fmt.Errorf("failed to unmount %s%s: %v", mountPoint, edetail, err)
		}
	} else if runtime.GOOS == "linux" {
		cmd := exec.Command("umount", mountPoint)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to unmount %s: %v", mountPoint, err)
		}
	}

	return nil
}

type systemEntry struct {
	ContentHint string `plist:"content-hint,omitempty" xml:"content-hint,omitempty"`
	DevEntry    string `plist:"dev-entry,omitempty" xml:"dev-entry,omitempty"`
	MountPoint  string `plist:"mount-point,omitempty" xml:"mount-point,omitempty"`
}

type image struct {
	Autodiskmount  bool          `plist:"autodiskmount,omitempty" xml:"autodiskmount,omitempty"`
	BlockCount     int64         `plist:"blockcount,omitempty" xml:"blockcount,omitempty"`
	BlockSize      int64         `plist:"blocksize,omitempty" xml:"blocksize,omitempty"`
	DiskImages2    bool          `plist:"diskimages2,omitempty" xml:"diskimages2,omitempty"`
	HdidPID        int64         `plist:"hdid-pid,omitempty" xml:"hdid-pid,omitempty"`
	IconPath       string        `plist:"icon-path,omitempty" xml:"icon-path,omitempty"`
	ImageEncrypted bool          `plist:"image-encrypted,omitempty" xml:"image-encrypted,omitempty"`
	ImagePath      string        `plist:"image-path,omitempty" xml:"image-path,omitempty"`
	ImageType      string        `plist:"image-type,omitempty" xml:"image-type,omitempty"`
	OwnerUID       int64         `plist:"owner-uid,omitempty" xml:"owner-uid,omitempty"`
	Removable      bool          `plist:"removable,omitempty" xml:"removable,omitempty"`
	SystemEntities []systemEntry `plist:"system-entities,omitempty" xml:"system-entities,omitempty"`
}

type HdiUtilInfo struct {
	Framework string  `plist:"framework,omitempty" xml:"framework,omitempty"`
	Revision  string  `plist:"revision,omitempty" xml:"revision,omitempty"`
	Vendor    string  `plist:"vendor,omitempty" xml:"vendor,omitempty"`
	Images    []image `plist:"images,omitempty" xml:"images,omitempty"`
}

func MountInfo() (*HdiUtilInfo, error) {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("hdiutil", "info", "-plist")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%v: %s", err, out)
		}
		var info HdiUtilInfo
		if err := plist.NewDecoder(bytes.NewReader(out)).Decode(&info); err != nil {
			return nil, fmt.Errorf("failed to decode hdiutil info plist: %v", err)
		}
		return &info, nil
	}
	return nil, fmt.Errorf("only supported on macOS")
}

func ExtractFromDMG(ipswPath, dmgPath, destPath string, pattern *regexp.Regexp) ([]string, error) {
	// check if filesystem DMG already exists (due to previous mount command)
	if _, err := os.Stat(dmgPath); os.IsNotExist(err) {
		dmgs, err := Unzip(ipswPath, "", func(f *zip.File) bool {
			return strings.EqualFold(filepath.Base(f.Name), dmgPath)
		})
		if err != nil {
			return nil, fmt.Errorf("failed to extract %s from IPSW: %v", dmgPath, err)
		}
		if len(dmgs) == 0 {
			return nil, fmt.Errorf("failed to find %s in IPSW", dmgPath)
		}
		defer os.Remove(dmgs[0])
	}

	Indent(log.Info, 2)(fmt.Sprintf("Mounting DMG %s", dmgPath))
	mountPoint, alreadyMounted, err := MountFS(dmgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to IPSW FS dmg: %v", err)
	}
	if alreadyMounted {
		Indent(log.Debug, 3)(fmt.Sprintf("%s already mounted", dmgPath))
	} else {
		defer func() {
			Indent(log.Debug, 2)(fmt.Sprintf("Unmounting %s", dmgPath))
			if err := Retry(3, 2*time.Second, func() error {
				return Unmount(mountPoint, false)
			}); err != nil {
				log.Errorf("failed to unmount DMG %s at %s: %v", dmgPath, mountPoint, err)
			}
		}()
	}

	var artifacts []string
	// extract files that match regex pattern
	if err := filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if pattern.MatchString(strings.TrimPrefix(path, mountPoint)) {
			fname := strings.TrimPrefix(path, mountPoint)
			fname = filepath.Join(destPath, fname)
			if err := os.MkdirAll(filepath.Dir(fname), 0750); err != nil {
				return fmt.Errorf("failed to create directory %s: %v", filepath.Join(destPath, filepath.Dir(fname)), err)
			}
			Indent(log.Info, 3)(fmt.Sprintf("Extracting to %s", fname))
			if err := Copy(path, fname); err != nil {
				return fmt.Errorf("failed to extract %s: %v", fname, err)
			}
			artifacts = append(artifacts, fname)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to extract File System files from IPSW: %v", err)
	}

	return artifacts, nil
}

func PkgUtilExpand(src, dst string) (string, error) {
	if runtime.GOOS == "darwin" {
		// cmd := exec.Command("pkgutil", "--expand-full", name, filepath.Join(os.TempDir(), "macosupd"))
		outDir := filepath.Join(dst, "macosupd")
		cmd := exec.Command("pkgutil", "--expand", src, outDir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%v: %s", err, out)
		}
		return outDir, nil
	}
	return "", fmt.Errorf("only supported on macOS")
}
