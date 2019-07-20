package dyld

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"github.com/blacktop/ipsw/utils"
	"github.com/apex/log"
	"github.com/pkg/errors"
)

const (
	hdiutilPath = "/usr/bin/hdiutil"
	mountPoint  = "/tmp/ios"
)

// Extract extracts dyld_shared_cache from ipsw
func Extract(ipsw string) error {
	log.Info("Extracting dyld_shared_cache from IPSW")
	dmg, err := utils.Unzip(ipsw, "", ".dmg", 1024*1024*1024)
	if err != nil {
		return errors.Wrap(err, "failed extract dyld_shared_cache from ipsw")
	}
	defer os.Remove(dmg)

	log.Info("Mounting DMG")
	device, err := Mount(dmg)
	if err != nil {
		return errors.Wrapf(err, "failed to mount %s", dmg)
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

// Unzip - https://stackoverflow.com/a/24792688
// func Unzip(src, dest string) (string, error) {
// 	var dmgName string
// 	r, err := zip.OpenReader(src)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer func() {
// 		if err := r.Close(); err != nil {
// 			panic(err)
// 		}
// 	}()

// 	os.MkdirAll(dest, 0755)

// 	// Closure to address file descriptors issue with all the deferred .Close() methods
// 	extractAndWriteFile := func(f *zip.File) error {
// 		rc, err := f.Open()
// 		if err != nil {
// 			return err
// 		}
// 		defer func() {
// 			if err := rc.Close(); err != nil {
// 				panic(err)
// 			}
// 		}()

// 		path := filepath.Join(dest, path.Base(f.Name))

// 		if f.FileInfo().IsDir() {
// 			os.MkdirAll(path, f.Mode())
// 		} else {
// 			os.MkdirAll(filepath.Dir(path), f.Mode())
// 			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
// 			if err != nil {
// 				return err
// 			}
// 			defer func() {
// 				if err := f.Close(); err != nil {
// 					panic(err)
// 				}
// 			}()

// 			_, err = io.Copy(f, rc)
// 			if err != nil {
// 				return err
// 			}
// 		}
// 		return nil
// 	}

// 	for _, f := range r.File {
// 		if strings.EqualFold(filepath.Ext(f.Name), ".dmg") {
// 			if f.UncompressedSize64 > 1024*1024*1024 {
// 				dmgName = path.Base(f.Name)
// 				err := extractAndWriteFile(f)
// 				if err != nil {
// 					return "", err
// 				}
// 			}
// 		}
// 	}

// 	return dmgName, nil
// }
