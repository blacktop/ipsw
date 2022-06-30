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

type extractConfig struct {
	CacheFolder string
	CacheRegex  string
	MountPoint  string
	Prefix      string
	Glob        string
	IsMacOS     bool
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
			config.CacheFolder = MacOSCacheFolder
			config.CacheRegex = MacOSCacheRegex
			config.IsMacOS = true
		} else {
			config.CacheFolder = IPhoneCacheFolder
			config.CacheRegex = IPhoneCacheRegex
		}

		if runtime.GOOS == "darwin" {
			os.MkdirAll(destPath, 0750)
			config.MountPoint = "/tmp/ios"
			config.Prefix = filepath.Join(config.MountPoint, config.CacheFolder) + "/"
			config.Glob = config.CacheFolder + "dyld_shared_cache_*"
		} else {
			if _, ok := os.LookupEnv("IPSW_IN_DOCKER"); ok {
				os.MkdirAll(filepath.Join("/data", destPath), 0750)
				config.MountPoint = "/mnt"
			} else {
				// Create temporary mount point
				os.MkdirAll(destPath, 0750)
				config.MountPoint = dmgs[0] + "_temp_mount"
				if err := os.Mkdir(config.MountPoint, 0750); err != nil {
					return errors.Wrapf(err, "Unable to create temporary mount point.")
				} else {
					defer os.RemoveAll(config.MountPoint)
				}
			}

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

		if config.IsMacOS {
			if len(arches) == 0 {
				selMatches := []string{}
				prompt := &survey.MultiSelect{
					Message:  "Which files would you like to extract:",
					Options:  matches,
					PageSize: 15,
				}
				if err := survey.AskOne(prompt, &selMatches); err != nil {
					if err == terminal.InterruptErr {
						log.Warn("Exiting...")
						return nil
					}
					return err
				}
				matches = selMatches
			} else {
				var filtered []string
				r := regexp.MustCompile(fmt.Sprintf("%s(%s)%s", config.CacheRegex, strings.Join(arches, "|"), CacheRegexEnding))
				for _, match := range matches {
					if r.MatchString(match) {
						filtered = append(filtered, match)
					}
				}

				if len(filtered) == 0 {
					return fmt.Errorf("no dyld_shared_cache files found matching the specified archs: %v", arches)
				}
				matches = filtered
			}
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
