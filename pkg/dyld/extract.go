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
	err := utils.Unmount(device, false)
	if err != nil {
		return errors.Wrapf(err, "failed to unmount %s", device)
	}
	return nil
}

// Extract extracts dyld_shared_cache from ipsw
func Extract(ipsw, destPath string) error {

	i, err := info.Parse(ipsw)
	if err != nil {
		return errors.Wrap(err, "failed to parse ipsw info")
	}

	dmgs, err := utils.Unzip(ipsw, "", func(f *zip.File) bool {
		if strings.EqualFold(filepath.Base(f.Name), i.GetOsDmg()) {
			return true
		}
		return false
	})
	if err != nil {
		return errors.Wrap(err, "failed extract dyld_shared_cache from ipsw")
	}

	if len(dmgs) == 1 {
		defer os.Remove(dmgs[0])

		var searchStr, searchStrMacOS, mountPoint string
		if runtime.GOOS == "darwin" {
			searchStr = "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64*"
			searchStrMacOS = "System/Library/dyld/dyld_shared_cache_arm64*"
			os.MkdirAll(destPath, os.ModePerm)
			mountPoint = "/tmp/ios"
		} else if runtime.GOOS == "linux" {
			searchStr = "root/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64*"
			os.MkdirAll(filepath.Join("/data", destPath), os.ModePerm)
			mountPoint = "/mnt"
		}

		utils.Indent(log.Info, 2)("Mounting DMG")
		if err := utils.Mount(dmgs[0], mountPoint); err != nil {
			return errors.Wrapf(err, "failed to mount %s", dmgs[0])
		}
		defer unmount(mountPoint)

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
		for _, match := range matches {
			dyldDest := filepath.Join(destPath, filepath.Base(match))
			utils.Indent(log.Info, 3)(fmt.Sprintf("Extracting %s to %s", match, dyldDest))
			err = utils.Cp(match, dyldDest)
			if err != nil {
				return err
			}
		}

	} else {
		return fmt.Errorf("dyld.Extract found more or less than one DMG (should only be one): %v", dmgs)
	}

	return nil
}
