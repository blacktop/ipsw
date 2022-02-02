package dyld

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/pkg/errors"
)

const (
	macOSCacheFolder     = "System/Library/dyld/"
	iOSCacheFolder       = "System/Library/Caches/com.apple.dyld/"
	driverKitCacheFolder = "System/DriverKit/System/Library/dyld/"

	iOSCacheRegex   = `System\/Library\/Caches\/com\.apple\.dyld\/dyld_shared_cache_`
	macOSCacheRegex = `System\/Library\/dyld\/dyld_shared_cache_`
	regexEnding     = `(\..*)?$`
)

const (
	CACHE_ARM64  = "arm64"
	CACHE_ARM64E = "arm64e"
	CACHE_INTEL  = "x86_64"
	CACHE_INTELH = "x86_64h"
)

type extractConfig struct {
	CacheFolder string
	CacheRegex  string
	MountPoint  string
	Prefix      string
	Glob        string
}

func unmount(device string) error {
	utils.Indent(log.Info, 2)("Unmounting DMG")
	err := utils.Unmount(device, false)
	if err != nil {
		return errors.Wrapf(err, "failed to unmount %s", device)
	}
	return nil
}

// Extract extracts dyld_shared_cache from ipsw
func Extract(ipsw, destPath string, arches []string) error {

	if runtime.GOOS == "windows" {
		return errors.New("dyld extraction is not supported on Windows")
	}

	i, err := info.Parse(ipsw)
	if err != nil {
		return errors.Wrap(err, "failed to parse ipsw info")
	}

	dmgs, err := utils.Unzip(ipsw, "", func(f *zip.File) bool {
		return strings.EqualFold(filepath.Base(f.Name), i.GetOsDmg())
	})
	if err != nil {
		return errors.Wrap(err, "failed extract dyld_shared_cache from ipsw")
	}

	if len(dmgs) == 1 {
		defer os.Remove(dmgs[0])

		var config extractConfig
		if utils.StrSliceContains(i.Plists.BuildManifest.SupportedProductTypes, "mac") {
			config.CacheFolder = macOSCacheFolder
			config.CacheRegex = macOSCacheRegex
		} else {
			config.CacheFolder = iOSCacheFolder
			config.CacheRegex = iOSCacheRegex
		}

		if runtime.GOOS == "darwin" {
			os.MkdirAll(destPath, os.ModePerm)
			config.MountPoint = "/tmp/ios"
			config.Prefix = filepath.Join(config.MountPoint, config.CacheFolder) + "/"
			config.Glob = config.CacheFolder + "dyld_shared_cache_*"
		} else {
			os.MkdirAll(filepath.Join("/data", destPath), os.ModePerm)
			config.MountPoint = "/mnt"
			config.Prefix = filepath.Join(config.MountPoint, config.CacheFolder) + "/"
			config.Glob = "root/" + config.CacheFolder + "dyld_shared_cache_*"
		}

		utils.Indent(log.Info, 2)("Mounting DMG")
		if err := utils.Mount(dmgs[0], config.MountPoint); err != nil {
			return errors.Wrapf(err, "failed to mount %s", dmgs[0])
		}
		defer unmount(config.MountPoint)

		matches, err := filepath.Glob(filepath.Join(config.MountPoint, config.Glob))
		if err != nil {
			return err
		}

		if len(arches) == 0 {
			prompt := &survey.MultiSelect{
				Message:  "Which files would you like to extract:",
				Options:  utils.TrimPrefixStrSlice(matches, config.Prefix),
				PageSize: 15,
			}
			if err := survey.AskOne(prompt, &matches); err != nil {
				if err == terminal.InterruptErr {
					log.Warn("Exiting...")
					return nil
				}
				return err
			}
		} else {
			var filtered []string
			for _, arch := range arches {
				r := regexp.MustCompile(fmt.Sprintf("%s%s%s", config.CacheRegex, arch, regexEnding))
				for _, match := range matches {
					if r.MatchString(match) {
						filtered = append(filtered, match)
					}
				}
			}
			if len(filtered) == 0 {
				return fmt.Errorf("no dyld_shared_cache files found matching the specified archs: %v", arches)
			}
			matches = filtered
		}

		if len(matches) == 0 {
			return errors.Errorf("failed to find dyld_shared_cache(s) in ipsw: %s", ipsw)
		}

		for _, match := range matches {
			dyldDest := filepath.Join(destPath, filepath.Base(match))
			utils.Indent(log.Info, 3)(fmt.Sprintf("Extracting %s to %s", filepath.Base(match), dyldDest))
			err = utils.Cp(match, dyldDest)
			if err != nil {
				return err
			}
		}

	} else {
		return fmt.Errorf("found more or less than one DMG (should only be one): %v", dmgs)
	}

	return nil
}
