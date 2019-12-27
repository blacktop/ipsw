package dyld

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/utils"
	"github.com/pkg/errors"
)

// Extract extracts dyld_shared_cache from ipsw
func Extract(ipsw string) error {

	dmgs, err := utils.Unzip(ipsw, "", func(f *zip.File) bool {
		if strings.EqualFold(filepath.Ext(f.Name), ".dmg") {
			if f.UncompressedSize64 > 1024*1024*1024 {
				return true
			}
		}
		return false
	})
	if err != nil {
		return errors.Wrap(err, "failed extract dyld_shared_cache from ipsw")
	}

	if len(dmgs) == 1 {
		defer os.Remove(dmgs[0])

		var searchStr, dyldDest, mountPoint string
		baseName := strings.TrimSuffix(ipsw, filepath.Ext(ipsw))
		if runtime.GOOS == "darwin" {
			searchStr = "System/Library/Caches/com.apple.dyld/dyld_shared_cache_*"
			dyldDest = "dyld_shared_cache_" + baseName
			mountPoint = "/tmp/ios"
		} else if runtime.GOOS == "linux" {
			searchStr = "root/System/Library/Caches/com.apple.dyld/dyld_shared_cache_*"
			dyldDest = filepath.Join("/data", "dyld_shared_cache_"+baseName)
			mountPoint = "/mnt"
		}

		utils.Indent(log.Info, 2)("Mounting DMG")
		device, err := Mount(dmgs[0], mountPoint)
		if err != nil {
			return errors.Wrapf(err, "failed to mount %s", dmgs[0])
		}

		matches, err := filepath.Glob(filepath.Join(mountPoint, searchStr))
		if err != nil {
			return err
		}

		if len(matches) == 0 {
			return errors.Errorf("failed to find dyld_shared_cache in ipsw: %s", ipsw)
		}

		utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting %s to %s", matches[0], dyldDest))
		err = Copy(matches[0], dyldDest)
		if err != nil {
			return err
		}

		utils.Indent(log.Info, 2)("Unmounting DMG")
		err = Unmount(device)
		if err != nil {
			return errors.Wrapf(err, "failed to unmount %s", device)
		}

	} else {
		return fmt.Errorf("dyld.Extract found more or less than one DMG (should only be one): %v", dmgs)
	}

	return nil
}

// Copy copies a file from mounted DMG to host
func Copy(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)

	return nil
}

// Mount mounts a DMG with hdiutil
func Mount(image, mountPoint string) (string, error) {
	if runtime.GOOS == "darwin" {
		var attachRe = regexp.MustCompile(`/dev/disk[\d]+`)
		cmd := exec.Command("hdiutil", "attach", "-noverify", "-mountpoint", mountPoint, image)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%v: %s", err, out)
		}

		return string(attachRe.Find(out)), nil
	} else if runtime.GOOS == "linux" {
		cmd := exec.Command("apfs-fuse", image, mountPoint)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%v: %s", err, out)
		}
		return mountPoint, nil
	}

	return "", nil
}

// Unmount unmounts a DMG with hdiutil
func Unmount(deviceNode string) error {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("hdiutil", "detach", deviceNode)

		err := cmd.Run()
		if err != nil {
			return err
		}

		return nil

	} else if runtime.GOOS == "linux" {
		cmd := exec.Command("umount", deviceNode)

		err := cmd.Run()
		if err != nil {
			return err
		}

		return nil
	}
	return nil
}
