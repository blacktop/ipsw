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
)

type extractConfig struct {
	CacheFolder string
	CacheRegex  string
	MountPoint  string
	Prefix      string
	Glob        string
	IsMacOS     bool
}

// Extract extracts dyld_shared_cache from IPSW
func Extract(ipsw, destPath string, arches []string) error {

	if runtime.GOOS == "windows" {
		return fmt.Errorf("dyld extraction is not supported on Windows (see github.com/blacktop/go-apfs)")
	}

	i, err := info.Parse(ipsw)
	if err != nil {
		return fmt.Errorf("failed to parse IPSW: %v", err)
	}

	dmgs, err := utils.Unzip(ipsw, "", func(f *zip.File) bool {
		return strings.EqualFold(filepath.Base(f.Name), i.GetOsDmg())
	})
	if err != nil {
		return fmt.Errorf("failed to extract %s from IPSW: %v", i.GetOsDmg(), err)
	}
	if len(dmgs) == 0 {
		return fmt.Errorf("File System %s NOT found in IPSW", i.GetOsDmg())
	}
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

	utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting DMG %s", dmgs[0]))
	config.MountPoint, err = utils.MountFS(dmgs[0])
	if err != nil {
		return fmt.Errorf("failed to IPSW FS dmg: %v", err)
	}
	defer func() {
		utils.Indent(log.Info, 2)(fmt.Sprintf("Unmounting DMG %s", dmgs[0]))
		if err := utils.Unmount(config.MountPoint, false); err != nil {
			log.Errorf("failed to unmount File System DMG mount at %s: %v", dmgs[0], err)
		}
	}()

	if runtime.GOOS == "darwin" {
		if err := os.MkdirAll(destPath, 0750); err != nil {
			return fmt.Errorf("failed to create destination directory %s: %v", destPath, err)
		}
		config.Prefix = filepath.Join(config.MountPoint, config.CacheFolder) + "/"
		config.Glob = config.CacheFolder + "dyld_shared_cache_*"
	} else {
		if _, ok := os.LookupEnv("IPSW_IN_DOCKER"); ok {
			if err := os.MkdirAll(filepath.Join("/data", destPath), 0750); err != nil {
				return fmt.Errorf("failed to create destination directory %s: %v", destPath, err)
			}
		} else {
			// Create temporary mount point
			if err := os.MkdirAll(destPath, 0750); err != nil {
				return fmt.Errorf("failed to create destination directory %s: %v", destPath, err)
			}
			if err := os.MkdirAll(config.MountPoint, 0750); err != nil {
				return fmt.Errorf("failed to create temporary mount point %s: %v", config.MountPoint, err)
			} else {
				defer os.RemoveAll(config.MountPoint)
			}
		}
		config.Prefix = filepath.Join(config.MountPoint, config.CacheFolder) + "/"
		config.Glob = "root/" + config.CacheFolder + "dyld_shared_cache_*"
	}

	matches, err := filepath.Glob(filepath.Join(config.MountPoint, config.Glob))
	if err != nil {
		return fmt.Errorf("failed to glob %s: %v", config.Glob, err)
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
		return fmt.Errorf("failed to find dyld_shared_cache(s) in ipsw: %s", ipsw)
	}

	for _, match := range matches {
		dyldDest := filepath.Join(destPath, filepath.Base(match))
		utils.Indent(log.Info, 3)(fmt.Sprintf("Extracting %s to %s", filepath.Base(match), dyldDest))
		if err := utils.Cp(match, dyldDest); err != nil {
			return fmt.Errorf("failed to copy %s to %s: %v", match, dyldDest, err)
		}
	}

	return nil
}
