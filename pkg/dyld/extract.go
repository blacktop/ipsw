package dyld

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/pkg/errors"
)

func unmount(device string) error {
	utils.Indent(log.Info, 2)("Unmounting DMG")
	err := utils.Unmount(device)
	if err != nil {
		return errors.Wrapf(err, "failed to unmount %s", device)
	}
	return nil
}

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

		i, err := info.Parse(ipsw)
		if err != nil {
			return errors.Wrap(err, "failed to parse ipsw info")
		}
		folders := i.GetFolders()
		folder := folders[0]

		var searchStr, searchStrMacOS, dyldDest, mountPoint string
		if runtime.GOOS == "darwin" {
			searchStr = "System/Library/Caches/com.apple.dyld/dyld_shared_cache_*"
			searchStrMacOS = "System/Library/dyld/dyld_shared_cache_*"
			os.MkdirAll(folder, os.ModePerm)
			dyldDest = filepath.Join(folder, "dyld_shared_cache")
			mountPoint = "/tmp/ios"
		} else if runtime.GOOS == "linux" {
			searchStr = "root/System/Library/Caches/com.apple.dyld/dyld_shared_cache_*"
			os.MkdirAll(filepath.Join("/data", folder), os.ModePerm)
			dyldDest = filepath.Join("/data", folder, "dyld_shared_cache")
			mountPoint = "/mnt"
		}

		utils.Indent(log.Info, 2)("Mounting DMG")
		device, err := utils.Mount(dmgs[0], mountPoint)
		if err != nil {
			return errors.Wrapf(err, "failed to mount %s", dmgs[0])
		}
		defer unmount(device)

		matches, err := filepath.Glob(filepath.Join(mountPoint, searchStr))
		if err != nil {
			return err
		}

		if len(matches) == 0 {
			matches, err = filepath.Glob(filepath.Join(mountPoint, searchStrMacOS))
			if err != nil {
				return err
			}
			if len(matches) == 0 {
				return errors.Errorf("failed to find dyld_shared_cache in ipsw: %s", ipsw)
			}
		}

		utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting %s to %s", matches[0], dyldDest))
		err = utils.Cp(matches[0], dyldDest)
		if err != nil {
			return err
		}

		// Create symlinks for all the other folders to save space
		for _, folder = range folders[1:] {
			symlinkPath := filepath.Join(folder, "dyld_shared_cache")
			utils.Indent(log.Info, 2)(fmt.Sprintf("Creating symlink from %s to %s", dyldDest, symlinkPath))
			os.MkdirAll(folder, os.ModePerm)
			symlinkPath, err = filepath.Abs(symlinkPath)
			if err != nil {
				return errors.Wrapf(err, "failed to get abs path to %s", symlinkPath)
			}
			if _, err := os.Lstat(symlinkPath); err == nil {
				os.Remove(symlinkPath)
			}
			err = os.Symlink(dyldDest, symlinkPath)
			if err != nil {
				return errors.Wrapf(err, "failed to symlink %s to %s", dyldDest, symlinkPath)
			}
		}

	} else {
		return fmt.Errorf("dyld.Extract found more or less than one DMG (should only be one): %v", dmgs)
	}

	return nil
}
