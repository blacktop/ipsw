package dyld

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota/ridiff"
	"github.com/pkg/errors"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

var ErrNoCryptex = errors.New("cryptex-system NOT found in remote zip")
var ErrNoDscFound = errors.New("failed to find dyld_shared_cache(s)")
var ErrNoDscForArch = errors.New("no dyld_shared_cache files found matching the specified archs")

var DscArches = []string{
	"arm64", "arm64e", "x86_64", "x86_64h", "aot",
}

// DscDMGKind identifies which IPSW DMG a dyld_shared_cache extraction step
// reads from.
type DscDMGKind string

const (
	SystemOSDscDMG  DscDMGKind = "SystemOS"
	RosettaOSDscDMG DscDMGKind = "RosettaOS"
)

// DscExtractionStep is one DMG to extract dyld_shared_cache(s) from, with the
// arches to pull out of it (nil means all). AllowEmpty lets multi-DMG callers
// continue past a DMG that has no matching caches and report a miss only if no
// planned DMG yields artifacts.
type DscExtractionStep struct {
	Kind       DscDMGKind
	Arches     []string
	AllowEmpty bool
}

func IsDscNotFound(err error) bool {
	return errors.Is(err, ErrNoDscFound) || errors.Is(err, ErrNoDscForArch)
}

func GetDscPathsInMount(mountPoint string, driverKit, all bool) ([]string, error) {
	var matches []string
	var re *regexp.Regexp

	mountPoint = utils.MountedFilesystemRoot(mountPoint)

	if driverKit {
		re = regexp.MustCompile(filepath.Join(mountPoint, DriverKitCacheRegex))
	} else if all {
		re = regexp.MustCompile(filepath.Join(mountPoint, CacheUberRegex))
	} else {
		re = regexp.MustCompile(filepath.Join(mountPoint, CacheRegex))
	}

	if err := filepath.Walk(mountPoint, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			utils.Indent(log.Warn, 3)(fmt.Sprintf("failed to walk %s: %v", path, err))
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if re.MatchString(path) {
			matches = append(matches, path)
		}
		return nil
	}); err != nil {
		return nil, err // FIXME: this will never error
	}

	return matches, nil
}

// DscExtractionPlan returns the DMG extraction steps needed to cover the
// requested arches for the given IPSW. macOS 27+ moves the x86_64 family of
// dyld_shared_caches into the Cryptex1,RosettaOS DMG, so plans for those
// IPSWs can span two DMGs. driverKit affects whether empty secondary DMGs
// are fatal: DriverKit extraction with no explicit arch scans any available
// RosettaOS DMG opportunistically, but a RosettaOS image with no DriverKit
// caches should not fail a SystemOS result.
func DscExtractionPlan(i *info.Info, arches []string, driverKit bool) ([]DscExtractionStep, error) {
	if !macOSX86DscRequiresRosetta(i) {
		return dscExtractionPlan(arches, false, false, driverKit)
	}

	requiresRosettaMetadata := (len(arches) == 0 && !driverKit) || hasRosettaDscArch(arches)
	opportunisticRosettaMetadata := len(arches) == 0 && driverKit
	hasRosettaOS := false
	if requiresRosettaMetadata || opportunisticRosettaMetadata {
		if _, err := i.GetRosettaOsDmg(); err == nil {
			hasRosettaOS = true
		} else if !errors.Is(err, info.ErrorCryptexNotFound) {
			// a truly absent cryptex is handled below; anything else (e.g.
			// multiple RosettaOS DMGs) would otherwise masquerade as "absent"
			if requiresRosettaMetadata {
				return nil, fmt.Errorf("failed to determine RosettaOS DMG availability: %w", err)
			}
			log.Warnf("failed to determine optional RosettaOS DMG availability: %v; extracting SystemOS DriverKit caches only", err)
		}
	}
	if !hasRosettaOS && len(arches) == 0 && !driverKit {
		log.Warn("macOS 27+ moves x86_64 dyld_shared_cache(s) to the RosettaOS cryptex, but BuildManifest has no Cryptex1,RosettaOS; extracting SystemOS caches only")
	}
	return dscExtractionPlan(arches, hasRosettaOS, true, driverKit)
}

func dscExtractionPlan(arches []string, hasRosettaOS, requiresRosetta, driverKit bool) ([]DscExtractionStep, error) {
	if !requiresRosetta {
		return []DscExtractionStep{{Kind: SystemOSDscDMG, Arches: arches, AllowEmpty: driverKit && len(arches) == 0}}, nil
	}

	if len(arches) == 0 { // all arches: cover every DMG that carries DSCs
		steps := []DscExtractionStep{{Kind: SystemOSDscDMG, AllowEmpty: driverKit}}
		if hasRosettaOS {
			steps = append(steps, DscExtractionStep{Kind: RosettaOSDscDMG, AllowEmpty: driverKit})
		}
		return steps, nil
	}

	var systemArches []string
	var rosettaArches []string
	for _, arch := range arches {
		if isRosettaDscArch(arch) {
			rosettaArches = append(rosettaArches, arch)
		} else {
			systemArches = append(systemArches, arch)
		}
	}

	if len(rosettaArches) > 0 && !hasRosettaOS {
		return nil, fmt.Errorf("macOS 27+ x86_64 dyld_shared_cache requires Cryptex1,RosettaOS in BuildManifest")
	}

	steps := make([]DscExtractionStep, 0, 2)
	if len(systemArches) > 0 {
		steps = append(steps, DscExtractionStep{Kind: SystemOSDscDMG, Arches: systemArches})
	}
	if len(rosettaArches) > 0 {
		steps = append(steps, DscExtractionStep{Kind: RosettaOSDscDMG, Arches: rosettaArches})
	}
	return steps, nil
}

func macOSX86DscRequiresRosetta(i *info.Info) bool {
	if i == nil || i.Plists == nil || i.Plists.BuildManifest == nil {
		return false
	}
	if !utils.StrSliceContains(i.Plists.BuildManifest.SupportedProductTypes, "mac") {
		return false
	}
	return utils.Compare(i.Plists.BuildManifest.ProductVersion, "27.0") >= 0
}

func isRosettaDscArch(arch string) bool {
	switch arch {
	case "x86_64", "x86_64h", "aot":
		return true
	default:
		return false
	}
}

func hasRosettaDscArch(arches []string) bool {
	return slices.ContainsFunc(arches, isRosettaDscArch)
}

func dscArchRegexParts(arches []string) []string {
	parts := make([]string, 0, len(arches))
	for _, arch := range arches {
		switch arch {
		case "aot":
			parts = append(parts, "x86_64h?")
		default:
			parts = append(parts, regexp.QuoteMeta(arch))
		}
	}
	return parts
}

func dscPathRegex(driverkit, all bool) string {
	if driverkit {
		return DriverKitCacheRegex
	}
	if all {
		return CacheUberRegex
	}
	return CacheRegex
}

func ExtractFromDMG(i *info.Info, dmgPath, destPath, pemDB string, arches []string, driverkit, all bool) ([]string, error) {
	skipCleanup := false

	// For AEA-encrypted DMGs, check if the decrypted version already exists
	// (e.g. already extracted + mounted by a prior step).
	// Reuse it to avoid overwriting a mounted DMG's backing file.
	if filepath.Ext(dmgPath) == ".aea" {
		decryptedPath := strings.TrimSuffix(dmgPath, filepath.Ext(dmgPath))
		if _, err := os.Stat(decryptedPath); err == nil {
			dmgPath = decryptedPath
			skipCleanup = true
		}
	}

	if !skipCleanup {
		if filepath.Ext(dmgPath) == ".aea" {
			var err error
			dmgPath, err = aea.Decrypt(&aea.DecryptConfig{
				Input:    dmgPath,
				Output:   filepath.Dir(dmgPath),
				PemDB:    pemDB,
				Proxy:    "",    // TODO: make proxy configurable
				Insecure: false, // TODO: make insecure configurable
			})
			if err != nil {
				return nil, fmt.Errorf("failed to parse AEA encrypted DMG: %v", err)
			}
			defer os.Remove(dmgPath)
		}
	}

	utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting DMG %s", dmgPath))
	var alreadyMounted bool
	mountPoint, alreadyMounted, err := utils.MountDMG(dmgPath, "")
	if err != nil {
		return nil, fmt.Errorf("failed to IPSW FS dmg: %v", err)
	}
	if alreadyMounted {
		utils.Indent(log.Debug, 3)(fmt.Sprintf("%s already mounted", dmgPath))
	} else {
		defer func() {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Unmounting %s", dmgPath))
			if err := utils.Retry(3, 2*time.Second, func() error {
				return utils.Unmount(mountPoint, true)
			}); err != nil {
				log.Errorf("failed to unmount DMG %s at %s: %v", dmgPath, mountPoint, err)
			}
		}()
	}

	if runtime.GOOS == "darwin" {
		if err := os.MkdirAll(destPath, 0750); err != nil {
			return nil, fmt.Errorf("failed to create destination directory %s: %v", destPath, err)
		}
	} else {
		if _, ok := os.LookupEnv("IPSW_IN_DOCKER"); ok {
			if err := os.MkdirAll(filepath.Join("/data", destPath), 0750); err != nil {
				return nil, fmt.Errorf("failed to create destination directory %s: %v", destPath, err)
			}
		} else {
			if err := os.MkdirAll(destPath, 0750); err != nil {
				return nil, fmt.Errorf("failed to create destination directory %s: %v", destPath, err)
			}
		}
	}

	mountedRoot := utils.MountedFilesystemRoot(mountPoint)
	matches, err := GetDscPathsInMount(mountPoint, driverkit, all)
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w in DMG: %s", ErrNoDscFound, dmgPath)
	}

	if utils.StrSliceContains(i.Plists.BuildManifest.SupportedProductTypes, "mac") { // Is macOS IPSW
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
					return nil, nil
				}
				return nil, err
			}
			matches = selMatches
		} else {
			var filtered []string
			archPatterns := dscArchRegexParts(arches)
			r := regexp.MustCompile(fmt.Sprintf("%s(%s)%s", dscPathRegex(driverkit, all), strings.Join(archPatterns, "|"), CacheRegexEnding))
			for _, match := range matches {
				if r.MatchString(match) {
					filtered = append(filtered, match)
				}
			}

			if len(filtered) == 0 {
				return nil, fmt.Errorf("%w: %v", ErrNoDscForArch, arches)
			}
			matches = filtered
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("%w in DMG: %s", ErrNoDscFound, dmgPath)
	}

	var artifacts []string
	for _, match := range matches {
		dyldDest := filepath.Join(destPath, filepath.Base(match))
		if all {
			if rel, err := filepath.Rel(mountedRoot, match); err == nil && !strings.HasPrefix(rel, "..") {
				dyldDest = filepath.Join(destPath, rel)
			}
		}
		// TODO: remove this (was commented out because I added --json to `ipsw extract` so the higher level func is now where this is printed)
		// utils.Indent(log.Info, 3)(fmt.Sprintf("Extracting %s to %s", filepath.Base(match), dyldDest))
		if err := utils.Copy(match, dyldDest); err != nil {
			return nil, fmt.Errorf("failed to copy %s to %s: %v", match, dyldDest, err)
		}
		artifacts = append(artifacts, dyldDest)
	}

	return artifacts, nil
}

// Extract extracts dyld_shared_cache from IPSW
func Extract(ipsw, destPath, pemDB string, arches []string, driverkit, all bool) ([]string, error) {

	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("dyld extraction is not supported on Windows (see github.com/blacktop/go-apfs)")
	}

	i, err := info.Parse(ipsw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPSW: %v", err)
	}

	steps, err := DscExtractionPlan(i, arches, driverkit)
	if err != nil {
		return nil, err
	}

	var artifacts []string
	var emptyErr error
	for _, step := range steps {
		dmgPath, err := dmgPathForDscStep(i, step.Kind)
		if err != nil {
			return nil, err
		}

		localDMGPath, cleanup, err := extractDmgFromIPSWIfNeeded(ipsw, dmgPath)
		if err != nil {
			return nil, err
		}

		stepArtifacts, err := ExtractFromDMG(i, localDMGPath, destPath, pemDB, step.Arches, driverkit, all)
		cleanup()
		if err != nil {
			if step.AllowEmpty && IsDscNotFound(err) {
				if emptyErr == nil {
					emptyErr = err
				}
				utils.Indent(log.Debug, 2)(fmt.Sprintf("No matching dyld_shared_cache(s) in optional %s DMG; continuing", step.Kind))
				continue
			}
			return nil, err
		}
		if stepArtifacts == nil {
			// nil artifacts with no error means the user interrupted the
			// interactive cache selection; don't prompt for remaining DMGs
			return artifacts, nil
		}
		artifacts = append(artifacts, stepArtifacts...)
	}

	if len(artifacts) == 0 && emptyErr != nil {
		return nil, emptyErr
	}

	return artifacts, nil
}

func dmgPathForDscStep(i *info.Info, kind DscDMGKind) (string, error) {
	switch kind {
	case RosettaOSDscDMG:
		dmgPath, err := i.GetRosettaOsDmg()
		if err != nil {
			return "", fmt.Errorf("failed to get RosettaOS DMG containing the x86_64 dyld_shared_cache(s): %v", err)
		}
		return dmgPath, nil
	case SystemOSDscDMG:
		dmgPath, err := i.GetSystemOsDmg()
		if err != nil {
			dmgPath, err = i.GetFileSystemOsDmg()
			if err != nil {
				return "", fmt.Errorf("failed to get DMG containing the dyld_shared_caches: %v", err)
			}
		}
		return dmgPath, nil
	default:
		return "", fmt.Errorf("unsupported dyld_shared_cache DMG kind: %s", kind)
	}
}

func extractDmgFromIPSWIfNeeded(ipsw, dmgPath string) (string, func(), error) {
	// Check if filesystem DMG already exists (due to previous mount command).
	if _, err := os.Stat(dmgPath); err == nil {
		return dmgPath, func() {}, nil
	}

	tmpDIR, err := os.MkdirTemp("", "ipsw_extract_dyld")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temporary directory: %v", err)
	}
	cleanup := func() { os.RemoveAll(tmpDIR) }

	dmgs, err := utils.Unzip(ipsw, tmpDIR, func(f *zip.File) bool {
		return strings.EqualFold(f.Name, dmgPath) || strings.EqualFold(filepath.Base(f.Name), dmgPath)
	})
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to extract %s from IPSW: %v", dmgPath, err)
	}
	if len(dmgs) == 0 {
		cleanup()
		return "", nil, fmt.Errorf("DMG %s NOT found in IPSW", dmgPath)
	}

	return dmgs[0], cleanup, nil
}

// RemoteCryptexPattern returns the ZIP member matcher used for remote OTA
// cryptex-system images.
func RemoteCryptexPattern(arches []string) *regexp.Regexp {
	if len(arches) == 0 {
		return regexp.MustCompile(`cryptex-system-(arm64e?|x86_64h?)$`)
	}
	parts := remoteCryptexArchPatterns(arches)
	if len(parts) == 0 {
		return regexp.MustCompile(`a^`)
	}
	return regexp.MustCompile(fmt.Sprintf(`cryptex-system-(%s)$`, strings.Join(parts, "|")))
}

func remoteCryptexArchPatterns(arches []string) []string {
	parts := make([]string, 0, len(arches))
	for _, arch := range arches {
		switch arch {
		case "arm64", "arm64e", "x86_64", "x86_64h":
			parts = append(parts, regexp.QuoteMeta(arch))
		case "aot":
			parts = append(parts, "x86_64h?")
		}
	}
	return parts
}

// RemoteCryptexFiles returns remote OTA cryptex-system members matching arches.
func RemoteCryptexFiles(files []*zip.File, arches []string) []*zip.File {
	re := RemoteCryptexPattern(arches)
	matches := make([]*zip.File, 0)
	for _, file := range files {
		if file.FileInfo().IsDir() || !re.MatchString(file.Name) {
			continue
		}
		matches = append(matches, file)
	}
	return matches
}

// ExtractFromRemoteCryptex extracts the dyld_shared_cache from the
// cryptex-system file in the given zip.Reader.
func ExtractFromRemoteCryptex(zr *zip.Reader, destPath, pemDB string, arches []string, driverkit, all bool) ([]string, error) {
	re := RemoteCryptexPattern(arches)
	for _, zf := range zr.File {
		if re.MatchString(zf.Name) {
			rc, err := zf.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open %s: %v", zf.Name, err)
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
					decor.AverageSpeed(decor.SizeB1024(0), "% .2f", decor.WCSyncWidth),
				),
			)
			// create proxy reader
			proxyReader := bar.ProxyReader(io.LimitReader(rc, total))
			defer proxyReader.Close()

			in, err := os.CreateTemp("", "cryptex-system")
			if err != nil {
				return nil, fmt.Errorf("failed to create temp file for %s: %v", zf.Name, err)
			}
			defer os.Remove(in.Name())

			log.Infof("Extracting %s from remote OTA", filepath.Base(zf.Name))
			io.Copy(in, proxyReader)
			// wait for our bar to complete and flush and close remote zip and temp file
			p.Wait()
			in.Close()

			out, err := os.CreateTemp("", "cryptex-system.decrypted.*.dmg")
			if err != nil {
				return nil, fmt.Errorf("failed to create temp file for %s: %v", in.Name(), err)
			}
			defer os.Remove(out.Name())
			out.Close()

			log.Infof("Patching %s to %s", zf.Name, out.Name())
			if err := ridiff.RawImagePatch("", in.Name(), out.Name(), 0); err != nil {
				return nil, fmt.Errorf("failed to patch %s: %v", zf.Name, err)

			}

			i, err := info.ParseZipFiles(zr.File)
			if err != nil {
				return nil, fmt.Errorf("failed to parse info from %s: %v", zf.Name, err)
			}

			artifacts, err := ExtractFromDMG(i, out.Name(), destPath, pemDB, arches, driverkit, all)
			if err != nil {
				tmpcopy := filepath.Join(os.TempDir(), filepath.Base(out.Name()))
				tcerr := utils.Copy(out.Name(), tmpcopy)
				exterr := fmt.Errorf("failed to extract 'dyld_shared_cache' from %s: %v", zf.Name, err)
				if tcerr != nil {
					return nil, fmt.Errorf("%v: attempted to copy downloaded file: failed to copy '%s' to '%s': %v", out.Name(), exterr, tmpcopy, tcerr)
				}
				return nil, fmt.Errorf("%v (copied downloaded file to '%s')", exterr, tmpcopy)
			}

			return artifacts, nil
		}
	}

	return nil, ErrNoCryptex
}
