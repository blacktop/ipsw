package diff

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	fwcmd "github.com/blacktop/ipsw/internal/commands/fw"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/ftab"
	"github.com/blacktop/ipsw/pkg/iboot"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	otapkg "github.com/blacktop/ipsw/pkg/ota"
	"github.com/blacktop/ipsw/pkg/ota/types"
)

// reDmgPayload matches numeric DMG payload filenames found in
// IPSWs (e.g. "090-43228-337.dmg.aea"). These are never OTAs.
var reDmgPayload = regexp.MustCompile(
	`[0-9]{3}-[0-9]{5}-[0-9]{3}\.dmg`,
)

var (
	reOTAFirmwareIm4p    = regexp.MustCompile(`\.im4p$`)
	reOTAAgfxFirmware    = regexp.MustCompile(`armfw_.*\.im4p$`)
	reOTAExclaveBundleFW = regexp.MustCompile(`.*exclavecore_bundle.*\.im4p$`)
)

// tryOpenOTA attempts to open path as an OTA and validate it.
// Returns (handle, info, nil) on success.
// Returns (nil, nil, nil) when the file is not an OTA (silent miss).
// Returns (nil, nil, err) on fatal errors (I/O, decryption failures
// for files that look like OTAs based on magic bytes).
func tryOpenOTA(path string, conf *Config) (*otapkg.AA, *info.Info, error) {
	base := filepath.Base(path)
	// Pre-reject obvious DMG payload names and bare .dmg files.
	if reDmgPayload.MatchString(base) {
		return nil, nil, nil
	}
	ext := strings.ToLower(filepath.Ext(base))
	if ext == ".dmg" {
		return nil, nil, nil
	}
	// Also reject .ipsw files — they are always IPSW archives.
	if ext == ".ipsw" {
		return nil, nil, nil
	}

	// Check magic to decide error handling strategy.
	// AEA/AA files are definitively OTA-like — propagate errors.
	// ZIP files are ambiguous (could be IPSW) — downgrade.
	likelyOTA, magicErr := isLikelyOTAByMagic(path)
	if magicErr != nil {
		return nil, nil, fmt.Errorf(
			"failed to probe %s: %w", path, magicErr,
		)
	}

	o, err := otapkg.Open(path, resolveOTAConfig(path, conf))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) ||
			errors.Is(err, os.ErrPermission) {
			return nil, nil, fmt.Errorf(
				"failed to open %s: %w", path, err,
			)
		}
		if likelyOTA {
			// File has AEA/AA magic — this is a real OTA error
			// (e.g. decryption failure, missing key).
			return nil, nil, fmt.Errorf(
				"failed to open OTA %s: %w "+
					"(check --key-db / --key-val / --insecure)",
				path, err,
			)
		}
		// Ambiguous ZIP — not an OTA.
		return nil, nil, nil
	}

	inf, err := o.Info()
	if err != nil {
		o.Close()
		if likelyOTA {
			// AEA/AA file opened but has no OTA metadata — odd
			// but could be a corrupt OTA. Propagate.
			return nil, nil, fmt.Errorf(
				"opened %s as OTA archive but failed to "+
					"parse metadata: %w",
				path, err,
			)
		}
		// ZIP that doesn't contain OTA plists — not an OTA.
		return nil, nil, nil
	}

	if inf.Plists == nil || inf.Plists.Type != "OTA" {
		o.Close()
		return nil, nil, nil
	}

	return o, inf, nil
}

// isLikelyOTAByMagic checks file magic to determine if the file
// is likely an OTA (AA or AEA format) rather than an ambiguous
// ZIP. Returns true for AA/AEA files where errors should be
// propagated, false for ZIPs where errors should be downgraded.
func isLikelyOTAByMagic(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	var buf [4]byte
	if _, err := io.ReadFull(f, buf[:]); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	switch magic.Magic(binary.LittleEndian.Uint32(buf[:])) {
	case magic.MagicYAA1, magic.MagicAA01:
		return true, nil
	}
	switch magic.Magic(binary.BigEndian.Uint32(buf[:])) {
	case magic.MagicAEA1:
		return true, nil
	}
	return false, nil
}

// resolveOTAConfig builds an ota.Config from the diff Config's
// AEA fields, including key-database lookup.
func resolveOTAConfig(path string, conf *Config) *otapkg.Config {
	oc := &otapkg.Config{
		SymmetricKey: conf.AEAKeyVal,
		Insecure:     conf.AEAInsecure,
	}
	// Use key DB when no explicit key is provided.
	if oc.SymmetricKey == "" && conf.AEAKeyDB != "" {
		if dbKey, err := lookupAEAKey(
			path, conf.AEAKeyDB,
		); err == nil && dbKey != "" {
			oc.SymmetricKey = dbKey
			log.Debug("Using AEA key from database")
		} else if err != nil {
			log.WithError(err).Warn(
				"Failed to lookup key in database",
			)
		}
	}
	return oc
}

// lookupAEAKey searches the JSON key database for a matching key.
// Mirrors cmd/ipsw/cmd/ota/ota.go:GetAEAKey() without importing
// the cmd package.
func lookupAEAKey(otaPath, keyDBPath string) (string, error) {
	if keyDBPath == "" {
		return "", nil
	}
	if otaPath == "" {
		return "", fmt.Errorf("otaPath cannot be empty")
	}

	candidates, err := otaFilenameCandidatesForLookup(otaPath)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(keyDBPath)
	if err != nil {
		return "", fmt.Errorf(
			"failed to read AEA key database: %v", err,
		)
	}

	var entries []types.AEAKeyEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return "", fmt.Errorf(
			"failed to parse AEA key database: %v", err,
		)
	}

	for _, entry := range entries {
		entryName := strings.TrimSuffix(
			entry.Filename,
			filepath.Ext(entry.Filename),
		)
		for _, candidate := range candidates {
			if strings.EqualFold(entryName, candidate) {
				return entry.Key, nil
			}
		}
	}

	return "", nil
}

func otaFilenameCandidatesForLookup(otaPath string) ([]string, error) {
	otaFilename := filepath.Base(otaPath)
	for {
		ext := strings.ToLower(filepath.Ext(otaFilename))
		if ext != ".aea" && ext != ".ota" && ext != ".zip" {
			break
		}
		otaFilename = strings.TrimSuffix(
			otaFilename, filepath.Ext(otaFilename),
		)
	}
	if otaFilename == "" || otaFilename == "." {
		return nil, fmt.Errorf("invalid OTA path: %s", otaPath)
	}

	candidates := []string{otaFilename}
	if idx := strings.LastIndex(otaFilename, "_"); idx >= 0 && idx+1 < len(otaFilename) {
		candidate := otaFilename[idx+1:]
		if candidate != otaFilename {
			candidates = append(candidates, candidate)
		}
	}

	return candidates, nil
}

// validateOTAScope rejects partial/delta and RSR OTAs that are
// not supported in Phase 1.
func validateOTAScope(inf *info.Info) error {
	if inf.Plists == nil || inf.Plists.OTAInfo == nil {
		return nil
	}
	props := &inf.Plists.OTAInfo.MobileAssetProperties
	if props.PrerequisiteBuild != "" {
		return fmt.Errorf(
			"partial/delta OTA detected (prerequisite build: %s); "+
				"`ipsw diff` requires full OTAs in this version — "+
				"use a full OTA or pre-patched directory inputs "+
				"via `ipsw ota patch`",
			props.PrerequisiteBuild,
		)
	}
	if props.SplatOnly {
		return fmt.Errorf(
			"RSR (Rapid Security Response) OTA detected; " +
				"`ipsw diff` does not support RSR OTAs directly — " +
				"use `ipsw ota patch rsr` to produce directory " +
				"inputs, then diff those directories",
		)
	}
	return nil
}

// unsupportedFlagsForOTAMode returns CLI flag names that are not
// fully supported when diffing OTA files. These flags will be
// skipped gracefully with a warning rather than hard-erroring.
func unsupportedFlagsForOTAMode(conf *Config) []string {
	var unsupported []string
	if conf.LowMemory {
		unsupported = append(unsupported, "--low-memory")
	}
	return unsupported
}

// isMacOSOTA checks whether the OTA targets macOS. Nil-safe for
// OTAs that lack a BuildManifest.
func isMacOSOTA(inf *info.Info) bool {
	if inf.Plists.BuildManifest != nil {
		return inf.IsMacOS()
	}
	if inf.Plists.OTAInfo != nil {
		name := inf.Plists.OTAInfo.MobileAssetProperties.ProductSystemName
		return strings.EqualFold(name, "macOS")
	}
	return false
}

// configureOTAContext populates Context metadata from parsed OTA
// info. Handles both BuildManifest-present and absent cases.
func configureOTAContext(
	ctx *Context, inf *info.Info, tmpDir string,
) {
	ctx.Info = inf
	ctx.InputMode = inputModeOTA

	if inf.Plists.BuildManifest != nil {
		ctx.Version = inf.Plists.BuildManifest.ProductVersion
		ctx.Build = inf.Plists.BuildManifest.ProductBuildVersion
		folder, err := inf.GetFolder()
		if err != nil {
			log.WithError(err).Warn(
				"failed to get folder from OTA BuildManifest",
			)
			ctx.Folder = filepath.Join(
				tmpDir, ctx.Build,
			)
		} else {
			ctx.Folder = filepath.Join(tmpDir, folder)
		}
		return
	}

	// Fallback: derive version/build from OTA-specific plists.
	var product string
	ctx.Version, ctx.Build, product = otaVersionBuildProduct(inf)
	// Include product in folder name to avoid collisions when
	// both sides share a build string.
	folderName := ctx.Build
	if product != "" {
		folderName = ctx.Build + "__" + product
	}
	ctx.Folder = filepath.Join(tmpDir, folderName)
}

// ensureOTAPayloadFilesystem materializes the OTA payload-backed
// filesystem once per OTA side so multiple diff consumers can
// reuse it without re-extracting payload files.
func ensureOTAPayloadFilesystem(ctx *Context) error {
	if ctx.payloadReady {
		return nil
	}
	if ctx.otaFile == nil {
		return fmt.Errorf("OTA handle not initialized")
	}

	payloadRoot := filepath.Join(ctx.Folder, "filesystem")
	if err := os.MkdirAll(payloadRoot, 0o755); err != nil {
		return fmt.Errorf("failed to create OTA payload filesystem dir: %w", err)
	}

	utils.Indent(log.Info, 2)(
		fmt.Sprintf("Extracting OTA payload filesystem to %s", payloadRoot),
	)
	if err := ctx.otaFile.GetPayloadFiles(".*", "", payloadRoot); err != nil {
		return fmt.Errorf("failed to extract OTA payload filesystem: %w", err)
	}

	ctx.payloadRoot = payloadRoot
	ctx.payloadReady = true
	return nil
}

// otaDiffMounts returns the OTA sources that should behave like
// IPSW filesystem-backed content for diff consumers.
func otaDiffMounts(ctx *Context) map[string]mount {
	mounts := make(map[string]mount, len(ctx.Mount)+1)
	maps.Copy(mounts, ctx.Mount)
	if ctx.payloadRoot != "" {
		mounts["filesystem"] = mount{MountPath: ctx.payloadRoot}
	}
	return mounts
}

func otaLaunchdSearchRoots(ctx *Context) []string {
	var roots []string
	if ctx.payloadRoot != "" {
		roots = append(roots, ctx.payloadRoot)
	}
	for _, name := range sortedMountNames(ctx.Mount) {
		roots = append(roots, ctx.Mount[name].MountPath)
	}
	return roots
}

// otaVersionBuildProduct extracts version, build, and a product
// identifier from OTA metadata when BuildManifest is absent.
func otaVersionBuildProduct(
	inf *info.Info,
) (version, build, product string) {
	if inf.Plists.AssetDataInfo != nil {
		version = inf.Plists.AssetDataInfo.ProductVersion
		build = inf.Plists.AssetDataInfo.Build
		product = inf.Plists.AssetDataInfo.ProductType
	}
	if inf.Plists.OTAInfo != nil {
		props := &inf.Plists.OTAInfo.MobileAssetProperties
		if version == "" {
			version = props.OSVersion
		}
		if build == "" {
			build = props.Build
		}
		if product == "" && len(props.SupportedDevices) > 0 {
			product = props.SupportedDevices[0]
		}
		if product == "" {
			product = props.ProductSystemName
		}
	}
	if version == "" {
		version = "unknown"
	}
	if build == "" {
		build = "unknown"
	}
	return version, build, product
}

// mountOTACryptexes extracts and mounts the system (and, when
// present, app) cryptexes from the OTA. Uses ctx.Folder as the
// extraction directory so Old and New don't collide.
func mountOTACryptexes(ctx *Context) error {
	outDir := ctx.Folder
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("failed to create cryptex output dir: %w", err)
	}

	systemDMG, err := extractOTASystemCryptex(ctx, outDir)
	if err != nil {
		return err
	}

	systemMount := filepath.Join(
		outDir, filepath.Base(systemDMG)+".mount",
	)
	mnt, err := mountCryptexDMG(systemDMG, systemMount)
	if err != nil {
		return fmt.Errorf("failed to mount system cryptex: %w", err)
	}
	ctx.Mount["SystemOS"] = mnt
	ctx.SystemOsDmgPath = mnt.DmgPath
	ctx.MountPath = mnt.MountPath
	ctx.IsMounted = mnt.IsMounted

	// App cryptex is optional; mount it when present so file and
	// MachO diffs see app-side content.
	appDMG, err := ctx.otaFile.ExtractCryptex("app", outDir)
	if err != nil {
		if errors.Is(err, otapkg.ErrCryptexNotFound) {
			utils.Indent(log.Debug, 2)("OTA has no app cryptex")
			return nil
		}
		unmountOTACryptexes(ctx.Build, ctx)
		return fmt.Errorf("failed to extract app cryptex: %w", err)
	}
	appMount := filepath.Join(
		outDir, filepath.Base(appDMG)+".mount",
	)
	appMnt, err := mountCryptexDMG(appDMG, appMount)
	if err != nil {
		unmountOTACryptexes(ctx.Build, ctx)
		return fmt.Errorf("failed to mount app cryptex: %w", err)
	}
	ctx.Mount["AppOS"] = appMnt
	return nil
}

// extractOTASystemCryptex extracts the system cryptex DMG. For
// macOS OTAs containing both arm64e and x86_64h variants, the
// arm64e variant is selected to match parseDSC's arch filter.
func extractOTASystemCryptex(ctx *Context, tmpDir string) (string, error) {
	if ctx.IsMacOS {
		dmg, err := ctx.otaFile.ExtractCryptex("system-arm64e", tmpDir)
		if err == nil {
			return dmg, nil
		}
		if !errors.Is(err, otapkg.ErrCryptexNotFound) {
			return "", fmt.Errorf("failed to extract arm64e system cryptex: %w", err)
		}
		// No arm64e variant — fall through to generic.
	}
	dmg, err := ctx.otaFile.ExtractCryptex("system", tmpDir)
	if err == nil {
		return dmg, nil
	}
	if errors.Is(err, otapkg.ErrCryptexNotFound) {
		return "", fmt.Errorf(
			"OTA does not contain a system cryptex; "+
				"`ipsw diff` currently requires cryptex-based "+
				"full OTAs — for older OTAs, extract DSC/kernel "+
				"via `ipsw ota extract` and diff those directly: %w",
			err,
		)
	}
	return "", fmt.Errorf("failed to extract system cryptex: %w", err)
}

func mountCryptexDMG(dmgPath, mountPoint string) (mount, error) {
	utils.Indent(log.Info, 2)(
		fmt.Sprintf("Mounting cryptex %s", dmgPath),
	)
	attachedMountPoint, alreadyMounted, err := utils.MountDMG(dmgPath, mountPoint)
	if err != nil {
		return mount{}, err
	}
	if alreadyMounted {
		utils.Indent(log.Info, 3)(
			fmt.Sprintf("%s already mounted", dmgPath),
		)
	}
	return mount{
		DmgPath:   dmgPath,
		MountPath: attachedMountPoint,
		IsMounted: alreadyMounted,
	}, nil
}

// unmountOTACryptexes unmounts and cleans up cryptex mounts for
// an OTA diff.
func unmountOTACryptexes(label string, ctx *Context) {
	for _, name := range sortedMountNames(ctx.Mount) {
		mnt := ctx.Mount[name]
		if mnt.IsMounted {
			utils.Indent(log.Info, 2)(
				fmt.Sprintf(
					"Leaving '%s' %s cryptex mounted",
					label, name,
				),
			)
			continue
		}
		utils.Indent(log.Info, 2)(
			fmt.Sprintf(
				"Unmounting '%s' %s cryptex", label, name,
			),
		)
		if err := utils.Retry(
			3, 2*time.Second, func() error {
				return utils.Unmount(mnt.MountPath, true)
			},
		); err != nil {
			utils.Indent(log.Error, 3)(
				fmt.Sprintf(
					"failed to unmount '%s' %s cryptex: %v",
					label, name, err,
				),
			)
		}
	}
}

// selectOTAKernelcachePair chooses which kernelcache members to
// extract from each OTA. Uses BuildManifest when present,
// otherwise falls back to shared-basename matching.
func selectOTAKernelcachePair(
	oldCtx, newCtx *Context,
) (oldMember, newMember string, err error) {
	oldHasManifest := oldCtx.Info != nil &&
		oldCtx.Info.Plists.BuildManifest != nil
	newHasManifest := newCtx.Info != nil &&
		newCtx.Info.Plists.BuildManifest != nil

	if oldHasManifest && newHasManifest {
		return selectKernelcacheViaManifest(oldCtx, newCtx)
	}
	return selectKernelcacheViaBasename(oldCtx, newCtx)
}

// macOSKernelcacheDevice mirrors the fixed device selector used
// by IPSW mode for macOS kernelcache extraction.
const macOSKernelcacheDevice = "Macmini9,1"

func selectKernelcacheViaManifest(
	oldCtx, newCtx *Context,
) (string, string, error) {
	oldKCs := oldCtx.Info.Plists.GetKernelCaches()
	newKCs := newCtx.Info.Plists.GetKernelCaches()

	models := make([]string, 0, len(oldKCs))
	for m := range oldKCs {
		models = append(models, m)
	}
	sort.Strings(models)
	// For macOS OTAs (which expose many device-specific
	// kernelcaches), prefer the same fixed device the IPSW path
	// uses so repeated runs and IPSW vs OTA diffs are consistent.
	if oldCtx.IsMacOS {
		if _, ok := oldKCs[macOSKernelcacheDevice]; ok {
			rest := make([]string, 0, len(models))
			for _, m := range models {
				if m != macOSKernelcacheDevice {
					rest = append(rest, m)
				}
			}
			models = append([]string{macOSKernelcacheDevice}, rest...)
		}
	}

	for _, kmodel := range models {
		oldPaths := oldKCs[kmodel]
		newPaths, ok := newKCs[kmodel]
		if !ok || len(newPaths) == 0 {
			continue
		}
		if len(oldPaths) == 0 {
			continue
		}
		// Use the raw manifest path basename for OTA lookup.
		// OTA files may be under prefixed paths like
		// AssetData/boot/kernelcache.release.iPhone18,1.
		oldName := filepath.Base(oldPaths[0])
		newName := filepath.Base(newPaths[0])

		// Find matching members in OTA file lists.
		oldMember := findOTAMember(oldCtx.otaFile, oldName)
		newMember := findOTAMember(newCtx.otaFile, newName)
		if oldMember == "" {
			return "", "", fmt.Errorf(
				"kernelcache %s not found in old OTA", oldName,
			)
		}
		if newMember == "" {
			return "", "", fmt.Errorf(
				"kernelcache %s not found in new OTA", newName,
			)
		}
		log.WithField("device", kmodel).Debug(
			"Selected kernelcache pair via BuildManifest",
		)
		return oldMember, newMember, nil
	}

	return "", "", fmt.Errorf(
		"no matching device model found in BuildManifests; " +
			"`ipsw diff` expects the same device type on both sides",
	)
}

func selectKernelcacheViaBasename(
	oldCtx, newCtx *Context,
) (string, string, error) {
	log.Warn(
		"BuildManifest missing from one or both OTAs; " +
			"falling back to basename matching for kernelcache",
	)
	reKC := regexp.MustCompile(`kernelcache\.`)
	oldKCs := collectOTAMembers(oldCtx.otaFile, reKC)
	newKCs := collectOTAMembers(newCtx.otaFile, reKC)

	// Build maps keyed by basename.
	oldByBase := make(map[string]string, len(oldKCs))
	for _, m := range oldKCs {
		oldByBase[filepath.Base(m)] = m
	}
	newByBase := make(map[string]string, len(newKCs))
	for _, m := range newKCs {
		newByBase[filepath.Base(m)] = m
	}

	// Find shared basenames, pick deterministically.
	var shared []string
	for base := range oldByBase {
		if _, ok := newByBase[base]; ok {
			shared = append(shared, base)
		}
	}
	sort.Strings(shared)

	if len(shared) == 0 {
		return "", "", fmt.Errorf(
			"no shared kernelcache basename found between OTAs "+
				"(old: %v, new: %v)",
			basenames(oldKCs), basenames(newKCs),
		)
	}

	pick := shared[0]
	log.WithField("kernelcache", pick).Debug(
		"Selected kernelcache pair via basename fallback",
	)
	return oldByBase[pick], newByBase[pick], nil
}

// findOTAMember finds an OTA file matching name. Tries exact
// basename match first, then suffix match to handle OTA paths
// like AssetData/boot/<name>.
func findOTAMember(o *otapkg.AA, name string) string {
	// First pass: exact basename.
	for _, f := range o.Files() {
		if f.IsDir() {
			continue
		}
		if filepath.Base(f.Name()) == name {
			return f.Name()
		}
	}
	// Second pass: suffix match (handles path-prefixed entries).
	suffix := "/" + name
	for _, f := range o.Files() {
		if f.IsDir() {
			continue
		}
		if strings.HasSuffix(f.Name(), suffix) {
			return f.Name()
		}
	}
	return ""
}

// collectOTAMembers returns all non-dir OTA file names matching re.
func collectOTAMembers(o *otapkg.AA, re *regexp.Regexp) []string {
	var out []string
	for _, f := range o.Files() {
		if f.IsDir() {
			continue
		}
		if re.MatchString(f.Name()) {
			out = append(out, f.Name())
		}
	}
	return out
}

func basenames(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Base(p)
	}
	return out
}

// extractOTAKernelcache extracts a specific kernelcache member
// from the OTA, decompresses it, and sets ctx.Kernel.Path.
func extractOTAKernelcache(
	ctx *Context, memberName, outputDir string,
) error {
	f, err := ctx.otaFile.Open(memberName, false)
	if err != nil {
		return fmt.Errorf(
			"failed to open kernelcache %s in OTA: %w",
			memberName, err,
		)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf(
			"failed to read kernelcache %s: %w",
			memberName, err,
		)
	}

	comp, err := kernelcache.ParseImg4Data(data)
	if err != nil {
		return fmt.Errorf(
			"failed to parse kernelcache IMG4: %w", err,
		)
	}

	kdata, err := kernelcache.DecompressData(comp)
	if err != nil {
		return fmt.Errorf(
			"failed to decompress kernelcache: %w", err,
		)
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf(
			"failed to create output dir: %w", err,
		)
	}

	outPath := filepath.Join(
		outputDir, filepath.Base(memberName),
	)
	if err := os.WriteFile(outPath, kdata, 0o644); err != nil {
		return fmt.Errorf(
			"failed to write kernelcache: %w", err,
		)
	}

	ctx.Kernel.Path = outPath
	return nil
}

// parseOTAIBoot extracts and parses the primary iBoot payload
// from a direct OTA. Mirrors the IPSW path by preferring
// iBoot.*.im4p members.
func parseOTAIBoot(ctx *Context) (*iboot.IBoot, error) {
	var candidates []string
	reIboot := regexp.MustCompile(`iBoot\..*\.im4p$`)

	for _, f := range ctx.otaFile.Files() {
		if f.IsDir() {
			continue
		}
		if reIboot.MatchString(f.Name()) {
			candidates = append(candidates, f.Name())
		}
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("failed to find iBoot im4p in OTA")
	}

	rc, err := ctx.otaFile.Open(candidates[0], false)
	if err != nil {
		return nil, fmt.Errorf("failed to open iBoot im4p %s: %w", candidates[0], err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read iBoot im4p %s: %w", candidates[0], err)
	}

	im4p, err := img4.ParsePayload(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse iBoot im4p %s: %w", candidates[0], err)
	}
	payload, err := im4p.GetData()
	if err != nil {
		return nil, fmt.Errorf("failed to decode iBoot im4p %s: %w", candidates[0], err)
	}

	return iboot.Parse(payload)
}

// diffFirmwaresFromOTA extracts im4p firmware files from both
// OTA handles and generates a firmware MachO diff.
func diffFirmwaresFromOTA(
	oldCtx, newCtx *Context, conf *mcmd.DiffConfig,
) (*mcmd.MachoDiff, error) {
	diff := &mcmd.MachoDiff{
		Updated: make(map[string]string),
	}

	prev := make(map[string]*mcmd.DiffInfo)
	if err := forEachOTAFirmware(oldCtx.otaFile, func(
		name string, m *macho.File,
	) error {
		prev[name] = mcmd.GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf(
			"failed to parse firmwares in 'Old' OTA: %w", err,
		)
	}

	next := make(map[string]*mcmd.DiffInfo)
	if err := forEachOTAFirmware(newCtx.otaFile, func(
		name string, m *macho.File,
	) error {
		next[name] = mcmd.GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf(
			"failed to parse firmwares in 'New' OTA: %w", err,
		)
	}

	if err := diff.Generate(prev, next, conf); err != nil {
		return nil, err
	}
	return diff, nil
}

// forEachOTAFirmware iterates im4p firmware files in an OTA,
// opens each as a MachO, and calls handler.
func forEachOTAFirmware(
	o *otapkg.AA,
	handler func(string, *macho.File) error,
) error {
	for _, f := range o.Files() {
		if f.IsDir() || !reOTAFirmwareIm4p.MatchString(f.Name()) {
			continue
		}
		rc, err := o.Open(f.Name(), false)
		if err != nil {
			log.WithError(err).Debugf(
				"failed to open firmware %s", f.Name(),
			)
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			log.WithError(err).Debugf(
				"failed to read firmware %s", f.Name(),
			)
			continue
		}
		im4p, err := img4.ParsePayload(data)
		if err != nil {
			log.WithError(err).Debugf(
				"failed to parse im4p %s", f.Name(),
			)
			continue
		}
		payload, err := im4p.GetData()
		if err != nil {
			log.WithError(err).Debugf(
				"failed to get im4p data %s", f.Name(),
			)
			continue
		}

		switch {
		case reOTAAgfxFirmware.MatchString(f.Name()):
			ft, err := ftab.Parse(bytes.NewReader(payload))
			if err != nil {
				return fmt.Errorf("failed to parse ftab: %w", err)
			}
			for _, entry := range ft.Entries {
				entryData, err := io.ReadAll(entry)
				if err != nil {
					ft.Close()
					return fmt.Errorf("failed to read ftab entry: %w", err)
				}
				m, err := macho.NewFile(bytes.NewReader(entryData))
				if err != nil {
					continue
				}
				name := "agx_" + filepath.Base(string(entry.Tag[:]))
				if err := handler(name, m); err != nil {
					m.Close()
					ft.Close()
					return fmt.Errorf("failed to handle firmware %s: %w", name, err)
				}
				m.Close()
			}
			ft.Close()

		case reOTAExclaveBundleFW.MatchString(f.Name()):
			tmpDir, err := os.MkdirTemp("", "ipsw_ota_exclave_fw")
			if err != nil {
				return fmt.Errorf("failed to create temp directory for exclave cores: %w", err)
			}
			out, err := fwcmd.ExtractExclaveCores(payload, tmpDir)
			if err != nil {
				_ = os.RemoveAll(tmpDir)
				return fmt.Errorf("failed to split exclave apps FW: %w", err)
			}
			for _, path := range out {
				m, err := macho.Open(path)
				if err != nil {
					continue
				}
				name := "exclave_" + filepath.Base(path)
				if err := handler(name, m); err != nil {
					m.Close()
					_ = os.RemoveAll(tmpDir)
					return fmt.Errorf("failed to handle firmware %s: %w", name, err)
				}
				m.Close()
			}
			if err := os.RemoveAll(tmpDir); err != nil {
				log.WithError(err).Debug("failed to remove temporary exclave firmware directory")
			}

		default:
			m, err := macho.NewFile(bytes.NewReader(payload))
			if err != nil {
				// Not a MachO (e.g. raw firmware blob) — skip.
				continue
			}
			name := filepath.Base(f.Name())
			if err := handler(name, m); err != nil {
				m.Close()
				return fmt.Errorf(
					"failed to handle firmware %s: %w",
					name, err,
				)
			}
			m.Close()
		}
	}
	return nil
}

// collectFeatureFlagsFromMounts walks mounted volumes for
// /System/Library/FeatureFlags plists and collects their content.
func collectFeatureFlagsFromMounts(
	mounts map[string]mount, out map[string]string,
) error {
	featureFlagsDir := filepath.Join(
		"System", "Library", "FeatureFlags",
	)
	for _, name := range sortedMountNames(mounts) {
		mnt := mounts[name]
		ffDir := filepath.Join(mnt.MountPath, featureFlagsDir)
		if _, err := os.Stat(ffDir); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf(
				"failed to stat FeatureFlags in %s: %w",
				name, err,
			)
		}
		if err := filepath.Walk(ffDir, func(
			path string, fi os.FileInfo, err error,
		) error {
			if err != nil {
				if os.IsPermission(err) {
					return nil
				}
				return nil
			}
			if fi.IsDir() || !strings.HasSuffix(path, ".plist") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf(
					"failed to read plist %s: %w", path, err,
				)
			}
			rel, err := filepath.Rel(ffDir, path)
			if err != nil {
				rel = filepath.Base(path)
			}
			out[rel] = string(data)
			return nil
		}); err != nil {
			return fmt.Errorf(
				"failed to walk FeatureFlags in %s: %w",
				name, err,
			)
		}
	}
	return nil
}

// launchdConfigFromRoots finds and parses launchd from one of the
// provided filesystem roots, preferring /sbin/launchd when present.
func launchdConfigFromRoots(roots []string) (string, error) {
	var candidates []string
	for _, root := range roots {
		if root == "" {
			continue
		}
		if _, err := os.Stat(root); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", fmt.Errorf("failed to stat launchd search root %s: %w", root, err)
		}
		if err := filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				if os.IsPermission(err) {
					return nil
				}
				return nil
			}
			if fi.IsDir() {
				return nil
			}
			if filepath.Base(path) == "launchd" {
				candidates = append(candidates, path)
			}
			return nil
		}); err != nil {
			return "", fmt.Errorf("failed to walk launchd search root %s: %w", root, err)
		}
	}

	if len(candidates) == 0 {
		return "", fmt.Errorf("launchd not found under any OTA source root")
	}

	sort.Slice(candidates, func(i, j int) bool {
		iPreferred := strings.HasSuffix(candidates[i], filepath.Join("sbin", "launchd"))
		jPreferred := strings.HasSuffix(candidates[j], filepath.Join("sbin", "launchd"))
		if iPreferred != jPreferred {
			return iPreferred
		}
		return candidates[i] < candidates[j]
	})

	launchdPath := candidates[0]
	m, err := macho.Open(launchdPath)
	if err != nil {
		fat, ferr := macho.OpenFat(launchdPath)
		if ferr != nil {
			return "", fmt.Errorf("failed to open launchd: %w", err)
		}
		defer fat.Close()
		m = fat.Arches[len(fat.Arches)-1].File
	} else {
		defer m.Close()
	}

	sec := m.Section("__TEXT", "__config")
	if sec == nil {
		return "", fmt.Errorf("launchd at %s has no __TEXT,__config section", launchdPath)
	}
	data, err := sec.Data()
	if err != nil {
		return "", fmt.Errorf("failed to read launchd config: %w", err)
	}
	return string(data), nil
}
