package dyld

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota/ridiff"
	"github.com/vbauerster/mpb/v7"
	"github.com/vbauerster/mpb/v7/decor"
)

type extractConfig struct {
	CacheFolder string
	CacheRegex  string
	MountPoint  string
	Prefix      string
	Glob        string
	IsMacOS     bool
}

func ExtractFromDMG(i *info.Info, dmgPath, destPath string, arches []string) error {
	var err error

	var config extractConfig
	if utils.StrSliceContains(i.Plists.BuildManifest.SupportedProductTypes, "mac") {
		config.CacheFolder = MacOSCacheFolder
		config.CacheRegex = MacOSCacheRegex
		config.IsMacOS = true
	} else {
		config.CacheFolder = IPhoneCacheFolder
		config.CacheRegex = IPhoneCacheRegex
	}

	utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting DMG %s", dmgPath))
	config.MountPoint, err = utils.MountFS(dmgPath)
	if err != nil {
		return fmt.Errorf("failed to IPSW FS dmg: %v", err)
	}
	defer func() {
		utils.Indent(log.Info, 2)(fmt.Sprintf("Unmounting DMG %s", dmgPath))
		if err := utils.Unmount(config.MountPoint, false); err != nil {
			log.Errorf("failed to unmount File System DMG mount at %s: %v", dmgPath, err)
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
		return fmt.Errorf("failed to find dyld_shared_cache(s) in DMG: %s", dmgPath)
	}

	for _, match := range matches {
		dyldDest := filepath.Join(destPath, filepath.Base(match))
		utils.Indent(log.Info, 3)(fmt.Sprintf("Extracting %s to %s", filepath.Base(match), dyldDest))
		if err := utils.Copy(match, dyldDest); err != nil {
			return fmt.Errorf("failed to copy %s to %s: %v", match, dyldDest, err)
		}
	}

	return nil
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

	systemDMG, err := i.GetSystemOsDmg()
	if err != nil {
		return fmt.Errorf("failed to get system DMG: %v", err)
	}
	dmgs, err := utils.Unzip(ipsw, "", func(f *zip.File) bool {
		return strings.EqualFold(filepath.Base(f.Name), systemDMG)
	})
	if err != nil {
		return fmt.Errorf("failed to extract %s from IPSW: %v", systemDMG, err)
	}
	if len(dmgs) == 0 {
		return fmt.Errorf("File System %s NOT found in IPSW", systemDMG)
	}
	defer os.Remove(dmgs[0])

	return ExtractFromDMG(i, dmgs[0], destPath, arches)
}

func ExtractFromRemoteCryptex(zr *zip.Reader, destPath string, arches []string) error {
	found := false

	for _, zf := range zr.File {
		if regexp.MustCompile(`cryptex-system-arm64?e$`).MatchString(zf.Name) {
			found = true
			rc, err := zf.Open()
			if err != nil {
				return fmt.Errorf("failed to open cryptex-system-arm64e: %v", err)
			}
			defer rc.Close()
			// setup progress bar
			var total int64 = int64(zf.UncompressedSize64)
			p := mpb.New(
				mpb.WithWidth(60),
				mpb.WithRefreshRate(180*time.Millisecond),
			)
			bar := p.New(total,
				mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding("-").Rbound("|"),
				mpb.PrependDecorators(
					decor.CountersKibiByte("\t% .2f / % .2f"),
				),
				mpb.AppendDecorators(
					decor.OnComplete(decor.AverageETA(decor.ET_STYLE_GO), "✅ "),
					decor.Name(" ] "),
					decor.AverageSpeed(decor.UnitKiB, "% .2f"),
				),
			)
			// create proxy reader
			proxyReader := bar.ProxyReader(io.LimitReader(rc, total))
			defer proxyReader.Close()

			in, err := os.CreateTemp("", "cryptex-system-arm64e")
			if err != nil {
				return fmt.Errorf("failed to create temp file for cryptex-system-arm64e: %v", err)
			}
			defer os.Remove(in.Name())

			log.Info("Extracting cryptex-system-arm64e from remote OTA")
			io.Copy(in, proxyReader)
			// wait for our bar to complete and flush and close remote zip and temp file
			p.Wait()
			in.Close()

			out, err := os.CreateTemp("", "cryptex-system-arm64e.decrypted.*.dmg")
			if err != nil {
				return fmt.Errorf("failed to create temp file for cryptex-system-arm64e.decrypted: %v", err)
			}
			defer os.Remove(out.Name())
			out.Close()

			log.Info("Patching cryptex-system-arm64e")
			if err := ridiff.RawImagePatch(in.Name(), out.Name()); err != nil {
				return fmt.Errorf("failed to patch cryptex-system-arm64e: %v", err)

			}

			i, err := info.ParseZipFiles(zr.File)
			if err != nil {
				return fmt.Errorf("failed to parse info from cryptex-system-arm64e: %v", err)
			}

			folder, err := i.GetFolder()
			if err != nil {
				log.Errorf("failed to get folder from remote zip metadata: %v", err)
			}
			destPath = filepath.Join(destPath, folder)

			if err := ExtractFromDMG(i, out.Name(), destPath, arches); err != nil {
				return fmt.Errorf("failed to extract dyld_shared_cache from cryptex-system-arm64e: %v", err)
			}

			return nil
		}
	}

	if !found {
		return fmt.Errorf("cryptex-system-arm64e NOT found in remote zip")
	}

	return nil
}
