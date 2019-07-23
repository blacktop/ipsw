package dyld

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/utils"
	"github.com/pkg/errors"
)

const (
	hdiutilPath = "/usr/bin/hdiutil"
	mountPoint  = "/tmp/ios"
)

// Extract extracts dyld_shared_cache from ipsw
func Extract(ipsw string) error {
	log.Info("Extracting dyld_shared_cache from IPSW")
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

		log.Info("Mounting DMG")
		device, err := Mount(dmgs[0])
		if err != nil {
			return errors.Wrapf(err, "failed to mount %s", dmgs[0])
		}
		matches, err := filepath.Glob(filepath.Join(mountPoint, "System/Library/Caches/com.apple.dyld/dyld_shared_cache_*"))
		if err != nil {
			return err
		}
		if len(matches) == 0 {
			return errors.Errorf("failed to find dyld_shared_cache in ipsw: %s", ipsw)
		}

		log.Infof("Extracting %s to ./dyld_shared_cache", matches[0])
		err = Copy(matches[0], "dyld_shared_cache")
		if err != nil {
			return err
		}
		log.Info("Unmounting DMG")
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
func Mount(image string) (string, error) {
	var attachRe = regexp.MustCompile(`/dev/disk[\d]+`)
	cmd := exec.Command(hdiutilPath, "attach", "-noverify", "-mountpoint", mountPoint, image)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, out)
	}

	return string(attachRe.Find(out)), nil
}

// Unmount unmounts a DMG with hdiutil
func Unmount(deviceNode string) error {
	cmd := exec.Command(hdiutilPath, "detach", deviceNode)

	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}
