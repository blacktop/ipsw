// Package diff provides a way to diff two ipsws
package diff

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	dcmd "github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/internal/commands/dwarf"
	"github.com/blacktop/ipsw/internal/commands/ent"
	kcmd "github.com/blacktop/ipsw/internal/commands/kernel"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	mountcmd "github.com/blacktop/ipsw/internal/commands/mount"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/iboot"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	otapkg "github.com/blacktop/ipsw/pkg/ota"
	"github.com/blacktop/ipsw/pkg/signature"
	"golang.org/x/exp/maps"
)

type kernel struct {
	Path    string
	Version *kernelcache.Version
	Kexts   []string
}

type mount struct {
	DmgPath      string
	MountPath    string
	IsMounted    bool
	CleanupPaths []string
}

type PlistDiff struct {
	New     map[string]string `json:"new,omitempty"`
	Removed []string          `json:"removed,omitempty"`
	Updated map[string]string `json:"changed,omitempty"`
}

type FileDiff struct {
	New     map[string][]string `json:"new,omitempty"`
	Removed map[string][]string `json:"removed,omitempty"`
	// Updated map[string]string `json:"changed,omitempty"`
}

type IBootDiff struct {
	Versions []string            `json:"versions,omitempty"`
	New      map[string][]string `json:"new,omitempty"`
	Removed  map[string][]string `json:"removed,omitempty"`
}

type Config struct {
	Title         string
	IpswOld       string
	IpswNew       string
	KDKs          []string
	LaunchD       bool
	Firmware      bool
	Features      bool
	Files         bool
	Localizations bool
	Sandbox       bool
	CStrings      bool
	FuncStarts    bool
	Entitlements  bool
	AllowList     []string
	BlockList     []string
	PemDB         string
	Signatures    string
	Output        string
	Verbose       bool
	AEAKeyDB      string
	AEAKeyVal     string
	AEAInsecure   bool
	// Cache holds the persistent-cache lifecycle options used in IPSW
	// mode. A zero value disables persistent caching and falls back to
	// the per-orchestrator MemoryStore that the directory/OTA paths use.
	Cache CacheConfig
}

// CacheConfig mirrors the CLI flags that govern the SQLite-backed diff
// cache. It is consumed by [Diff.Diff] after parsing IPSW Info structs;
// non-IPSW input modes ignore it.
type CacheConfig struct {
	// Dir overrides the default cache directory. Empty means use
	// os.UserCacheDir() + "/ipsw/diffs/".
	Dir string
	// NoCache disables persistent storage; a temp SQLite DB is used and
	// removed on exit.
	NoCache bool
	// Clean deletes any existing cache DB for this pair before opening.
	Clean bool
	// MaxBytes is the LRU eviction threshold applied to the cache
	// directory after the run finishes. Zero disables eviction.
	MaxBytes int64
}

// Context is the context for the diff
type Context struct {
	IPSWPath        string
	InputMode       inputMode
	Info            *info.Info
	Version         string
	Build           string
	Folder          string
	Mount           map[string]mount
	SystemOsDmgPath string
	MountPath       string
	IsMounted       bool
	IsMacOS         bool
	Kernel          kernel
	DSC             string
	Webkit          string
	KDK             string
	PemDB           string

	// otaFile is the parsed OTA archive. Nil unless InputMode == inputModeOTA.
	otaFile *otapkg.AA
	// payloadRoot is the extracted OTA payload filesystem root.
	payloadRoot  string
	payloadReady bool

	mu *sync.Mutex
}

// Diff is the diff
type Diff struct {
	Title string `json:"title,omitempty"`

	Old Context `json:"-"`
	New Context `json:"-"`

	Kexts         *mcmd.MachoDiff            `json:"kexts,omitempty"`
	KDKs          string                     `json:"kdks,omitempty"`
	Ents          map[string]string          `json:"ents,omitempty"`
	Dylibs        *mcmd.MachoDiff            `json:"dylibs,omitempty"`
	Machos        map[string]*mcmd.MachoDiff `json:"machos,omitempty"`
	Firmwares     *mcmd.MachoDiff            `json:"firmwares,omitempty"`
	IBoot         *IBootDiff                 `json:"iboot,omitempty"`
	Launchd       string                     `json:"launchd,omitempty"`
	Sandbox       string                     `json:"sandbox,omitempty"`
	Features      map[string]*PlistDiff      `json:"features,omitempty"`
	Files         *FileDiff                  `json:"files,omitempty"`
	Localizations map[string]*PlistDiff      `json:"localizations,omitempty"`
	tmpDir        string                     `json:"-"`
	conf          *Config
	oldSession    *mountcmd.Session // IPSW mode only: mounts each OS volume once
	newSession    *mountcmd.Session // IPSW mode only: mounts each OS volume once
	sameKernel    bool              // IPSW mode only: BuildManifest digests match
	sameVolumes   map[string]bool   // IPSW mode only: dmg type -> BuildManifest digests match
	// store is the cache backend used by orchestrators; nil means each
	// orchestrator allocates its own ephemeral MemoryStore. The CLI sets
	// this via SetStore so a single SQLiteStore spans every task in a run.
	store storage.Store
}

// SetStore installs a shared cache backend used by the volume-major and
// top-level orchestrators. Passing nil restores the default behavior of
// allocating a per-run MemoryStore for each orchestrator call.
func (d *Diff) SetStore(s storage.Store) { d.store = s }

// New news the diff
func New(conf *Config) *Diff {
	if len(conf.KDKs) == 0 {
		return &Diff{
			Title: conf.Title,
			Old: Context{
				IPSWPath: conf.IpswOld,
				Mount:    make(map[string]mount),
			},
			New: Context{
				IPSWPath: conf.IpswNew,
				Mount:    make(map[string]mount),
			},
			conf: conf,
		}
	}
	return &Diff{
		Title: conf.Title,
		Old: Context{
			IPSWPath: conf.IpswOld,
			Mount:    make(map[string]mount),
			KDK:      conf.KDKs[0],
		},
		New: Context{
			IPSWPath: conf.IpswNew,
			Mount:    make(map[string]mount),
			KDK:      conf.KDKs[1],
		},
		conf: conf,
	}
}

func (d *Diff) SetOutput(output string) {
	if d.conf == nil {
		d.conf = &Config{Output: output}
	} else {
		d.conf.Output = output
	}
}

func (d *Diff) TitleToFilename() string {
	var out strings.Builder
	lastUnderscore := false
	writeUnderscore := func() {
		if lastUnderscore {
			return
		}
		out.WriteByte('_')
		lastUnderscore = true
	}

	for _, r := range d.Title {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '_', r == '-', r == ',':
			out.WriteRune(r)
			lastUnderscore = false
		case unicode.IsSpace(r), r == '.', r == '(', r == ')', r == '/', r == '\\', r == ':':
			writeUnderscore()
		default:
			writeUnderscore()
		}
	}

	filename := strings.Trim(out.String(), "_")
	if filename == "" {
		return "diff"
	}

	return filename
}

func ipswSessionExtractDir(tmpDir, side string) string {
	return filepath.Join(tmpDir, "ipsw-session", side)
}

func (d *Diff) getInfo() (err error) {
	mode, err := detectInputMode(d.Old.IPSWPath, d.New.IPSWPath)
	if err != nil {
		return err
	}
	d.Old.PemDB = d.conf.PemDB
	d.New.PemDB = d.conf.PemDB

	if mode == inputModeDirectory {
		d.Old.InputMode = inputModeDirectory
		d.New.InputMode = inputModeDirectory
		configureDirectoryContext(&d.Old)
		configureDirectoryContext(&d.New)

		if d.Title == "" {
			d.Title = fmt.Sprintf("%s .vs %s", d.Old.Build, d.New.Build)
		}

		return nil
	}

	// Probe both sides for OTA before committing to IPSW mode.
	oldOTA, oldInfo, oldErr := tryOpenOTA(d.Old.IPSWPath, d.conf)
	newOTA, newInfo, newErr := tryOpenOTA(d.New.IPSWPath, d.conf)

	// Handle fatal errors — clean up any opened handle.
	if oldErr != nil {
		if newOTA != nil {
			newOTA.Close()
		}
		return fmt.Errorf("failed to probe 'Old' input: %w", oldErr)
	}
	if newErr != nil {
		if oldOTA != nil {
			oldOTA.Close()
		}
		return fmt.Errorf("failed to probe 'New' input: %w", newErr)
	}

	// Classify symmetrically.
	switch {
	case oldOTA != nil && newOTA != nil:
		// Both are OTAs — validate scope (Phase 1: full OTAs only).
		if err := validateOTAScope(oldInfo); err != nil {
			oldOTA.Close()
			newOTA.Close()
			return fmt.Errorf("'Old' OTA: %w", err)
		}
		if err := validateOTAScope(newInfo); err != nil {
			oldOTA.Close()
			newOTA.Close()
			return fmt.Errorf("'New' OTA: %w", err)
		}

		d.Old.otaFile = oldOTA
		d.New.otaFile = newOTA
		configureOTAContext(&d.Old, oldInfo, d.tmpDir)
		configureOTAContext(&d.New, newInfo, d.tmpDir)

		if isMacOSOTA(oldInfo) || isMacOSOTA(newInfo) {
			d.Old.IsMacOS = true
			d.New.IsMacOS = true
		}

		if d.Title == "" {
			d.Title = fmt.Sprintf(
				"%s (%s) .vs %s (%s)",
				d.Old.Version, d.Old.Build,
				d.New.Version, d.New.Build,
			)
		}
		return nil

	case oldOTA == nil && newOTA == nil:
		// Neither is OTA — fall through to IPSW mode.

	default:
		// Mixed: one OTA, one not.
		if oldOTA != nil {
			oldOTA.Close()
		}
		if newOTA != nil {
			newOTA.Close()
		}
		return fmt.Errorf(
			"inputs must both be IPSW files, OTA files, " +
				"or directories of patched OTA DMGs",
		)
	}

	// IPSW mode.
	d.Old.InputMode = inputModeIPSW
	d.New.InputMode = inputModeIPSW

	d.Old.Info, err = info.Parse(d.Old.IPSWPath)
	if err != nil {
		return fmt.Errorf("failed to parse 'Old' IPSW: %v", err)
	}
	d.New.Info, err = info.Parse(d.New.IPSWPath)
	if err != nil {
		return fmt.Errorf("failed to parse 'New' IPSW: %v", err)
	}

	d.Old.Version = d.Old.Info.Plists.BuildManifest.ProductVersion
	d.Old.Build = d.Old.Info.Plists.BuildManifest.ProductBuildVersion
	d.Old.Folder, err = d.Old.Info.GetFolder()
	if err != nil {
		log.Errorf("failed to get folder from 'Old' IPSW metadata: %v", err)
	}
	d.Old.Folder = filepath.Join(d.tmpDir, d.Old.Folder)

	d.New.Version = d.New.Info.Plists.BuildManifest.ProductVersion
	d.New.Build = d.New.Info.Plists.BuildManifest.ProductBuildVersion
	d.New.Folder, err = d.New.Info.GetFolder()
	if err != nil {
		log.Errorf("failed to get folder from 'New' IPSW metadata: %v", err)
	}
	d.New.Folder = filepath.Join(d.tmpDir, d.New.Folder)

	if d.Title == "" {
		d.Title = fmt.Sprintf("%s (%s) .vs %s (%s)", d.Old.Version, d.Old.Build, d.New.Version, d.New.Build)
	}

	if d.Old.Info.IsMacOS() || d.New.Info.IsMacOS() {
		d.Old.IsMacOS = true
		d.New.IsMacOS = true
	}

	return nil
}

// Diff diffs the diff
func (d *Diff) Diff() (err error) {

	d.tmpDir, err = os.MkdirTemp(os.TempDir(), "ipsw-diff")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(d.tmpDir)

	if err := d.getInfo(); err != nil {
		return err
	}
	d.indexIdenticalIPSWArtifacts()

	// Install the persistent diff cache for IPSW mode. Directory and
	// OTA inputs lack BuildManifest digests so they fall back to the
	// per-orchestrator MemoryStore that acquireStore allocates.
	if cleanup := d.openCacheStore(); cleanup != nil {
		defer cleanup()
	}

	// Close OTA handles when done (after all extractions).
	if d.Old.otaFile != nil {
		defer d.Old.otaFile.Close()
	}
	if d.New.otaFile != nil {
		defer d.New.otaFile.Close()
	}

	directoryMode := d.Old.InputMode == inputModeDirectory
	otaMode := d.Old.InputMode == inputModeOTA

	if directoryMode {
		if unsupported := unsupportedFlagsForDirectoryMode(d.conf); len(unsupported) > 0 {
			log.Warnf("Directory inputs do not support %s; skipping those sections", strings.Join(unsupported, ", "))
		}
		log.Info("Mounting patched OTA DMGs")
		if err := d.mountSystemOsDMGs(); err != nil {
			return fmt.Errorf("failed to mount DMGs: %v", err)
		}
		defer d.unmountSystemOsDMGs()
	}

	if otaMode {
		if unsupported := unsupportedFlagsForOTAMode(d.conf); len(unsupported) > 0 {
			log.Warnf("OTA mode does not support %s; skipping those sections", strings.Join(unsupported, ", "))
		}
	}

	// Top-level kernel-derived tasks run in source order before mount
	// sessions exist: parseKernelcache populates d.Kexts and Kernel.Path
	// (which the sandbox task consumes); parseKDKs runs against the
	// per-side KDK paths; parseSandboxProfiles is gated on sameKernel.
	{
		var pre []TopLevelTask
		if directoryMode {
			log.Debug("Skipping KERNELCACHES for directory inputs")
		} else if d.sameKernel {
			log.Info("Skipping KERNELCACHES (BuildManifest digest unchanged)")
		} else {
			log.Info("Diffing KERNELCACHES")
			pre = append(pre, newKextsTask(d))
		}
		if d.Old.KDK != "" && d.New.KDK != "" {
			log.Info("Diffing KDKS")
			pre = append(pre, newKDKsTask(d))
		}
		if err := d.runTopLevelTasks(context.Background(), pre); err != nil {
			log.WithError(err).Error("failed to run pre-mount top-level tasks")
		}
	}

	if d.conf.Sandbox && !directoryMode {
		if d.sameKernel {
			utils.Indent(log.Warn, 2)("Skipping Sandbox Profiles (kernelcache unchanged)")
		} else {
			log.Info("Diffing Sandbox Profiles")
			if err := d.runTopLevelTasks(context.Background(), []TopLevelTask{newSandboxTask(d)}); err != nil {
				log.WithError(err).Error("failed to diff sandbox profiles")
			}
		}
	}

	if !directoryMode && !otaMode {
		// IPSW mode: mount each OS volume once per side via a session, shared by
		// the DSC parse and every later feature. defer Close() here so it
		// dominates every session.Root() call across the feature passes.
		// Keep old/new extracted DMGs isolated; IPSWs often reuse the same DMG
		// filenames across builds, and DmgInIPSW treats an existing extraction as
		// a cache hit.
		d.oldSession = mountcmd.NewSession(d.Old.IPSWPath, &mountcmd.Config{
			PemDB:      d.conf.PemDB,
			ExtractDir: ipswSessionExtractDir(d.tmpDir, "old"),
		})
		d.newSession = mountcmd.NewSession(d.New.IPSWPath, &mountcmd.Config{
			PemDB:      d.conf.PemDB,
			ExtractDir: ipswSessionExtractDir(d.tmpDir, "new"),
		})
		defer d.oldSession.Close()
		defer d.newSession.Close()
		// IPSW mode no longer pre-mounts "sys" here. The volume-major
		// orchestrator (runIPSWVolumeJobsForMode) lazily mounts each volume
		// when its phase runs and releases it before moving on.
	} else if otaMode {
		if err := d.mountSystemOsDMGs(); err != nil {
			return fmt.Errorf("failed to mount DMGs: %v", err)
		}
		defer d.unmountSystemOsDMGs()
	}

	if directoryMode || otaMode {
		// Legacy feature-major paths for non-IPSW input modes.
		if otaMode || !d.dscVolumeUnchanged() {
			log.Info("Diffing DYLD_SHARED_CACHES")
			if err := d.parseDSC(); err != nil {
				log.WithError(err).Error("failed to parse DSCs")
			}
		}
		log.Info("Diffing MachOs")
		if err := d.parseMachos(); err != nil {
			log.WithError(err).Error("failed to parse MachOs")
		}
		if d.conf.LaunchD && otaMode {
			log.Info("Diffing launchd PLIST")
			if err := d.parseLaunchdPlists(); err != nil {
				log.WithError(err).Error("failed to parse launchd plists")
			}
		}
	}
	// IPSW mode: DSC, MachOs, launchd, features, localizations, entitlements,
	// and files are all dispatched by the volume-major orchestrator below.

	if d.conf.Firmware {
		var fw []TopLevelTask
		log.Info("Diffing Firmware")
		fw = append(fw, newFirmwaresTask(d))
		if !directoryMode {
			log.Info("Diffing iBoot")
			fw = append(fw, newIBootTask(d))
		}
		if err := d.runTopLevelTasks(context.Background(), fw); err != nil {
			log.WithError(err).Error("failed to run firmware top-level tasks")
		}
	}

	// IPSW-mode Feature Flags is handled by featuresJob via the volume-major
	// orchestrator (see runIPSWVolumeJobsForMode). OTA and Directory modes
	// still run the legacy parseFeatureFlags here.
	if d.conf.Features && (directoryMode || otaMode) {
		log.Info("Diffing Feature Flags")
		if err := d.parseFeatureFlags(); err != nil {
			log.WithError(err).Error("failed to parse feature flags")
		}
	}

	// IPSW-mode Localizations handled by locsJob via the orchestrator.
	if d.conf.Localizations && (directoryMode || otaMode) {
		log.Info("Diffing Localizations")
		if err := d.parseLocalizations(); err != nil {
			log.WithError(err).Error("failed to parse localizations")
		}
	}

	// IPSW-mode Entitlements handled by entsJob via the orchestrator.
	if d.conf.Entitlements && (directoryMode || otaMode) {
		log.Info("Diffing ENTITLEMENTS")
		d.Ents, err = d.parseEntitlements()
		if err != nil {
			log.WithError(err).Error("failed to parse entitlements")
		}
	}

	if err := d.runIPSWVolumeJobsForMode(directoryMode, otaMode); err != nil {
		log.WithError(err).Error("failed to run volume-major jobs")
	}

	return nil
}

// runIPSWVolumeJobsForMode dispatches the per-flag jobs that have been
// migrated to the volume-major orchestrator. OTA and Directory modes fall
// back to the legacy feature-major parser for Files; the other parsers
// (DSC, launchd) are handled outside this function for those modes.
//
// IPSW mode builds a job list from d.conf.* flags and runs the orchestrator.
// As more parsers are ported, additional entries get appended here.
func (d *Diff) runIPSWVolumeJobsForMode(directoryMode, otaMode bool) error {
	if directoryMode || otaMode {
		if d.conf.Files {
			log.Info("Diffing Files")
			if err := d.parseFiles(); err != nil {
				log.WithError(err).Error("failed to parse files")
			}
		}
		return nil
	}

	var jobs []Task

	// DSC always runs in IPSW mode (the existing behavior); the per-volume
	// skip in the orchestrator handles the "sys unchanged" case.
	if !d.dscVolumeUnchanged() {
		log.Info("Diffing DYLD_SHARED_CACHES")
		jobs = append(jobs, newDSCJob(d))
	} else {
		log.Info("Skipping DYLD_SHARED_CACHES (SystemOS DMG unchanged)")
	}

	if d.conf.LaunchD {
		if d.ipswVolumeUnchanged("fs") {
			log.Info("Skipping launchd PLIST (FileSystem DMG unchanged)")
		} else {
			log.Info("Diffing launchd PLIST")
			jobs = append(jobs, newLaunchdJob(d))
		}
	}

	if d.conf.Features {
		if d.allIPSWOSVolumesUnchanged() {
			log.Info("Skipping Feature Flags (OS DMGs unchanged)")
		} else {
			log.Info("Diffing Feature Flags")
			jobs = append(jobs, newFeaturesJob(d))
		}
	}

	if d.conf.Localizations {
		if d.allIPSWOSVolumesUnchanged() {
			log.Info("Skipping Localizations (OS DMGs unchanged)")
		} else {
			log.Info("Diffing Localizations")
			jobs = append(jobs, newLocalizationsJob(d))
		}
	}

	if d.conf.Entitlements {
		if d.allIPSWOSVolumesUnchanged() {
			log.Info("Skipping ENTITLEMENTS (OS DMGs unchanged)")
		} else {
			log.Info("Diffing ENTITLEMENTS")
			jobs = append(jobs, newEntitlementsJob(d))
		}
	}

	// MachOs always runs in IPSW mode (the existing behavior); the per-volume
	// skip in the orchestrator handles the "all OS DMGs unchanged" case.
	if d.allIPSWOSVolumesUnchanged() {
		log.Info("Skipping MachOs (OS DMGs unchanged)")
	} else {
		log.Info("Diffing MachOs")
		jobs = append(jobs, newMachosJob(d))
	}

	if d.conf.Files {
		log.Info("Diffing Files")
		jobs = append(jobs, newFilesJob(d))
	}

	if len(jobs) == 0 {
		return nil
	}
	return d.runIPSWVolumePhases(jobs)
}

// mountSystemOsDMGs mounts the OS volumes for OTA and directory inputs. IPSW
// mode instead mounts each volume once via a per-side mount.Session in Diff().
func (d *Diff) mountSystemOsDMGs() (err error) {
	switch d.Old.InputMode {
	case inputModeDirectory:
		log.Info("Mounting 'Old' patched OTA DMGs")
		if err := mountDirectoryDMGs(&d.Old); err != nil {
			return err
		}
		log.Info("Mounting 'New' patched OTA DMGs")
		if err := mountDirectoryDMGs(&d.New); err != nil {
			return err
		}
		return nil
	case inputModeOTA:
		log.Info("Extracting 'Old' OTA system cryptex")
		if err := mountOTACryptexes(&d.Old); err != nil {
			return err
		}
		log.Info("Extracting 'New' OTA system cryptex")
		if err := mountOTACryptexes(&d.New); err != nil {
			unmountOTACryptexes("Old", &d.Old)
			return err
		}
		return nil
	default:
		return fmt.Errorf("mountSystemOsDMGs: IPSW mode mounts via mount.Session, not this path")
	}
}

func (d *Diff) unmountSystemOsDMGs() error {
	if d.Old.InputMode == inputModeDirectory {
		releaseDirectoryMounts("Old", d.Old.Mount)
		releaseDirectoryMounts("New", d.New.Mount)
		return nil
	}
	if d.Old.InputMode == inputModeOTA {
		unmountOTACryptexes("Old", &d.Old)
		unmountOTACryptexes("New", &d.New)
		return nil
	}
	// IPSW mode unmounts via mount.Session.Close.
	return nil
}

func (d *Diff) extractKernelcaches() error {
	if d.Old.InputMode == inputModeOTA {
		oldMember, newMember, err := selectOTAKernelcachePair(&d.Old, &d.New)
		if err != nil {
			return fmt.Errorf("failed to select OTA kernelcache pair: %w", err)
		}
		if err := extractOTAKernelcache(&d.Old, oldMember, d.Old.Folder); err != nil {
			return fmt.Errorf("failed to extract 'Old' OTA kernelcache: %w", err)
		}
		if err := extractOTAKernelcache(&d.New, newMember, d.New.Folder); err != nil {
			return fmt.Errorf("failed to extract 'New' OTA kernelcache: %w", err)
		}
		return nil
	}

	// IPSW mode.
	if d.Old.IsMacOS || d.New.IsMacOS {
		if out, err := kernelcache.Extract(d.Old.IPSWPath, d.Old.Folder, "Macmini9,1"); err != nil {
			return fmt.Errorf("failed to extract kernelcaches from 'Old' IPSW: %v", err)
		} else {
			d.Old.Kernel.Path = maps.Keys(out)[0]
		}
		if out, err := kernelcache.Extract(d.New.IPSWPath, d.New.Folder, "Macmini9,1"); err != nil {
			return fmt.Errorf("failed to extract kernelcaches from 'New' IPSW: %v", err)
		} else {
			d.New.Kernel.Path = maps.Keys(out)[0]
		}
	} else {
		if _, err := kernelcache.Extract(d.Old.IPSWPath, d.Old.Folder, ""); err != nil {
			return fmt.Errorf("failed to extract kernelcaches from 'Old' IPSW: %v", err)
		}
		if _, err := kernelcache.Extract(d.New.IPSWPath, d.New.Folder, ""); err != nil {
			return fmt.Errorf("failed to extract kernelcaches from 'New' IPSW: %v", err)
		}
		for kmodel := range d.Old.Info.Plists.GetKernelCaches() {
			if _, ok := d.Old.Info.Plists.GetKernelCaches()[kmodel]; !ok {
				return fmt.Errorf("failed to find kernelcache for %s in 'Old' IPSW: `ipsw diff` expects you to compare 2 versions of the same IPSW device type", kmodel)
			} else if len(d.Old.Info.Plists.GetKernelCaches()[kmodel]) == 0 {
				return fmt.Errorf("failed to find kernelcache for %s in 'Old' IPSW", kmodel)
			}
			if _, ok := d.New.Info.Plists.GetKernelCaches()[kmodel]; !ok {
				return fmt.Errorf("failed to find kernelcache for %s in 'New' IPSW: `ipsw diff` expects you to compare 2 versions of the same IPSW device type", kmodel)
			} else if len(d.New.Info.Plists.GetKernelCaches()[kmodel]) == 0 {
				return fmt.Errorf("failed to find kernelcache for %s in 'New' IPSW", kmodel)
			}
			kcache1 := d.Old.Info.Plists.GetKernelCaches()[kmodel][0]
			kcache2 := d.New.Info.Plists.GetKernelCaches()[kmodel][0]
			d.Old.Kernel.Path = filepath.Join(d.Old.Folder, d.Old.Info.GetKernelCacheFileName(kcache1))
			d.New.Kernel.Path = filepath.Join(d.New.Folder, d.New.Info.GetKernelCacheFileName(kcache2))
			break // just use first kernelcache for now
		}
	}
	return nil
}

// ensureKernelcachePaths populates d.Old.Kernel.Path / d.New.Kernel.Path when
// they are empty. extractKernelcaches sets them as a side effect of the kexts
// task's Parse, but a warm cache hit on kexts SKIPS that Parse, so a sibling
// task that runs fresh (e.g. a partial-hit sandbox task) would otherwise find an
// empty path. Extraction treats an existing extraction as a cache hit, so this is
// idempotent and cheap; it is a no-op once either prior extraction has run.
func (d *Diff) ensureKernelcachePaths() error {
	if d.Old.Kernel.Path != "" && d.New.Kernel.Path != "" {
		return nil
	}
	return d.extractKernelcaches()
}

func (d *Diff) parseKernelcache() error {
	if err := d.extractKernelcaches(); err != nil {
		return err
	}

	m1, err := macho.Open(d.Old.Kernel.Path)
	if err != nil {
		return fmt.Errorf("failed to open kernelcache: %v", err)
	}
	d.Old.Kernel.Version, err = kernelcache.GetVersion(m1)
	if err != nil {
		return fmt.Errorf("failed to get kernelcache version: %v", err)
	}
	defer m1.Close()

	m2, err := macho.Open(d.New.Kernel.Path)
	if err != nil {
		return fmt.Errorf("failed to open kernelcache: %v", err)
	}
	d.New.Kernel.Version, err = kernelcache.GetVersion(m2)
	if err != nil {
		return fmt.Errorf("failed to get kernelcache version: %v", err)
	}
	defer m2.Close()

	sameKernel, err := filesSHA256Equal(d.Old.Kernel.Path, d.New.Kernel.Path)
	if err != nil {
		return fmt.Errorf("failed to compare extracted kernelcaches: %w", err)
	}
	if sameKernel {
		d.sameKernel = true
		utils.Indent(log.Warn, 2)("Skipping kernelcache symbolication and KEXT diff (extracted kernelcache unchanged)")
		return nil
	}

	// Wrapper bytes (UUID, build-root strings, embedded plist digests) often
	// differ across rebuilds of an otherwise-identical kernel. If every
	// functional segment (code, constants, mutable data, symbols) matches,
	// the kernel is functionally unchanged regardless of those differences.
	if kernelKeySegmentsEqual(m1, m2) {
		d.sameKernel = true
		utils.Indent(log.Warn, 2)("Skipping kernelcache symbolication and KEXT diff (functional segments unchanged; only UUID/build metadata differs)")
		return nil
	}

	var smap map[string]signature.SymbolMap
	if d.conf.Signatures != "" {
		smap = make(map[string]signature.SymbolMap)
		log.Info("Parsing Kernel Signatures")
		sigs, err := signature.Parse(d.conf.Signatures)
		if err != nil {
			return fmt.Errorf("failed to parse signatures: %v", err)
		}

		smap[m1.UUID().String()] = signature.NewSymbolMap()
		log.WithField("kernelcache", d.Old.Kernel.Path).Info("Symbolicating...")
		if err := smap[m1.UUID().String()].Symbolicate(d.Old.Kernel.Path, sigs, true); err != nil {
			log.Errorf("failed to symbolicate kernelcache: %v", err)
		}

		smap[m2.UUID().String()] = signature.NewSymbolMap()
		log.WithField("kernelcache", d.New.Kernel.Path).Info("Symbolicating...")
		if err := smap[m2.UUID().String()].Symbolicate(d.New.Kernel.Path, sigs, true); err != nil {
			log.Errorf("failed to symbolicate kernelcache: %v", err)
		}
	}

	d.Kexts, err = kcmd.Diff(m1, m2, &mcmd.DiffConfig{
		Markdown:   true,
		Color:      false,
		DiffTool:   "git",
		AllowList:  d.conf.AllowList,
		BlockList:  d.conf.BlockList,
		CStrings:   d.conf.CStrings,
		FuncStarts: d.conf.FuncStarts,
		SymMap:     smap,
		Verbose:    d.conf.Verbose,
	})
	if err != nil {
		return err
	}

	// // diff kexts
	// d.Old.Kernel.Kexts, err = kernelcache.KextList(d.Old.Kernel.Path, true)
	// if err != nil {
	// 	return err
	// }
	// d.New.Kernel.Kexts, err = kernelcache.KextList(d.New.Kernel.Path, true)
	// if err != nil {
	// 	return err
	// }
	// out, err := utils.GitDiff(
	// 	strings.Join(d.Old.Kernel.Kexts, "\n")+"\n",
	// 	strings.Join(d.New.Kernel.Kexts, "\n")+"\n",
	// 	&utils.GitDiffConfig{Color: false, Tool: "git"})
	// if err != nil {
	// 	return err
	// }
	// if len(out) == 0 {
	// 	d.Kexts = "- No differences found"
	// } else {
	// 	d.Kexts = "```diff\n" + out + "\n```"
	// }

	return nil
}

func (d *Diff) parseKDKs() (err error) {
	d.Old.KDK = kdkDwarfPath(d.Old.KDK)
	d.New.KDK = kdkDwarfPath(d.New.KDK)
	d.KDKs, err = dwarf.DiffStructures(d.Old.KDK, d.New.KDK, &dwarf.Config{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
	})
	d.Old.KDK = kdkDisplayPath(d.Old.KDK)
	d.New.KDK = kdkDisplayPath(d.New.KDK)
	return
}

func (d *Diff) parseDSC() error {
	return d.diffDSCBetweenRoots(d.Old.MountPath, d.New.MountPath)
}

// diffDSCBetweenRoots is the shared DSC diff implementation used by both
// the legacy parseDSC (OTA / Directory mode, which sets Context.MountPath
// via their own mount setup) and the volume-major dscJob (IPSW mode, which
// receives roots from the orchestrator's "sys" phase).
func (d *Diff) diffDSCBetweenRoots(oldRoot, newRoot string) error {
	dscOLD, err := openDSCFromMount(oldRoot, d.Old.IsMacOS, d.Old.InputMode, "Old")
	if err != nil {
		return err
	}
	defer dscOLD.Close()

	dscNEW, err := openDSCFromMount(newRoot, d.New.IsMacOS, d.New.InputMode, "New")
	if err != nil {
		return err
	}
	defer dscNEW.Close()

	/* DIFF WEBKIT */

	d.Old.Webkit, err = dcmd.GetWebkitVersion(dscOLD)
	if err != nil {
		log.WithError(err).Error("failed to get WebKit version from 'old' DSC")
	}

	d.New.Webkit, err = dcmd.GetWebkitVersion(dscNEW)
	if err != nil {
		log.WithError(err).Error("failed to get WebKit version from 'new' DSC")
	}

	d.Dylibs, err = dcmd.Diff(dscOLD, dscNEW, d.dscDiffConfig())
	if err != nil {
		return err
	}

	return nil
}

// openDSCFromMount finds the dyld_shared_cache under mountRoot (filtered to
// arm64e for macOS IPSWs when applicable) and opens the first match.
func openDSCFromMount(mountRoot string, isMacOS bool, mode inputMode, side string) (*dyld.File, error) {
	dscs, err := dyld.GetDscPathsInMount(mountRoot, false, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get DSC paths in %s: %v", mountRoot, err)
	}
	if len(dscs) == 0 {
		return nil, fmt.Errorf("no DSCs found in '%s' IPSW mount %s", side, mountRoot)
	}
	if isMacOS {
		var filtered []string
		r := regexp.MustCompile(fmt.Sprintf("%s(%s)%s", dyld.CacheRegex, "arm64e", dyld.CacheRegexEnding))
		for _, match := range dscs {
			if r.MatchString(match) {
				filtered = append(filtered, match)
			}
		}
		if len(filtered) == 0 && mode != inputModeOTA {
			return nil, fmt.Errorf("no dyld_shared_cache files found matching the specified archs 'arm64e'")
		}
		if len(filtered) > 0 {
			dscs = filtered
		}
	}
	dsc, err := dyld.Open(dscs[0])
	if err != nil {
		return nil, fmt.Errorf("failed to open DSC: %v", err)
	}
	return dsc, nil
}

func (d *Diff) ensureOTAPayloadFilesystems() error {
	if err := ensureOTAPayloadFilesystem(&d.Old); err != nil {
		return fmt.Errorf("failed to extract old OTA payload filesystem: %w", err)
	}
	if err := ensureOTAPayloadFilesystem(&d.New); err != nil {
		return fmt.Errorf("failed to extract new OTA payload filesystem: %w", err)
	}
	return nil
}

// parseEntitlements handles OTA and Directory input modes. IPSW mode is
// handled by entsJob via the volume-major orchestrator.
func (d *Diff) parseEntitlements() (map[string]string, error) {
	var oldMounts, newMounts map[string]mount
	switch d.Old.InputMode {
	case inputModeOTA:
		if err := d.ensureOTAPayloadFilesystems(); err != nil {
			return nil, err
		}
		oldMounts = otaDiffMounts(&d.Old)
		newMounts = otaDiffMounts(&d.New)
	case inputModeDirectory:
		oldMounts = d.Old.Mount
		newMounts = d.New.Mount
	default:
		return nil, fmt.Errorf("diff: parseEntitlements: IPSW mode uses entsJob via the volume-major orchestrator")
	}

	names := unionMountNames(oldMounts, newMounts)
	out := make(map[string]string)
	for _, name := range names {
		oldDB := make(map[string]string)
		if mnt, ok := oldMounts[name]; ok {
			ents, err := ent.GetDatabase(&ent.Config{
				Folder:            mnt.MountPath,
				LaunchConstraints: true,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to scan entitlements in old %s: %w", name, err)
			}
			maps.Copy(oldDB, ents)
		}
		newDB := make(map[string]string)
		if mnt, ok := newMounts[name]; ok {
			ents, err := ent.GetDatabase(&ent.Config{
				Folder:            mnt.MountPath,
				LaunchConstraints: true,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to scan entitlements in new %s: %w", name, err)
			}
			maps.Copy(newDB, ents)
		}
		rendered, err := renderEntitlementsDiff(oldDB, newDB)
		if err != nil {
			return nil, err
		}
		if entitlementsDiffHasContent(rendered) {
			out[name] = rendered
		}
	}
	return out, nil
}

// entitlementsDiffHasContent reports whether the rendered diff string
// contains actual diff data (as opposed to the "no differences" marker).
func entitlementsDiffHasContent(s string) bool {
	return s != "" && s != "- No differences found\n"
}

// renderEntitlementsDiff renders the markdown diff between two
// path-keyed entitlement databases. Shared by parseEntitlements
// (OTA/Directory) and entsJob (IPSW).
func renderEntitlementsDiff(oldDB, newDB map[string]string) (string, error) {
	return ent.DiffDatabases(oldDB, newDB, &ent.Config{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
	})
}

// parseMachos handles OTA and Directory input modes. IPSW mode is handled
// by machosJob via the volume-major orchestrator.
func (d *Diff) parseMachos() (err error) {
	conf := d.machoDiffConfig()
	if d.Old.InputMode == inputModeOTA {
		if err := d.ensureOTAPayloadFilesystems(); err != nil {
			return err
		}
		d.Machos, err = diffMachosInMounts(otaDiffMounts(&d.Old), otaDiffMounts(&d.New), conf)
		return
	}
	if d.Old.InputMode == inputModeDirectory {
		d.Machos, err = diffMachosInMounts(d.Old.Mount, d.New.Mount, conf)
		return
	}
	return fmt.Errorf("diff: parseMachos: IPSW mode uses machosJob via the volume-major orchestrator")
}

// machoDiffConfig builds the mcmd.DiffConfig used by all macho diff paths.
// Shared by parseMachos (OTA/Directory) and machosJob (IPSW).
func (d *Diff) machoDiffConfig() *mcmd.DiffConfig {
	return &mcmd.DiffConfig{
		Markdown:   true,
		Color:      false,
		DiffTool:   "git",
		AllowList:  d.conf.AllowList,
		BlockList:  d.conf.BlockList,
		CStrings:   d.conf.CStrings,
		FuncStarts: d.conf.FuncStarts,
		Verbose:    d.conf.Verbose,
	}
}

// dscDiffConfig builds the mcmd.DiffConfig used for dyld_shared_cache image
// diffs. Cache-image load-command bytes are noisy across point releases even
// when the image's rendered sections are unchanged, so DSC reports rely on the
// section/function/string/symbol legs and suppress load-command comparison.
func (d *Diff) dscDiffConfig() *mcmd.DiffConfig {
	conf := d.machoDiffConfig()
	conf.IgnoreLoadCommands = true
	return conf
}

// parseLaunchdPlists handles the OTA path (Directory mode is not supported
// for launchd). IPSW mode is handled by launchdJob via the volume-major
// orchestrator.
func (d *Diff) parseLaunchdPlists() error {
	if d.Old.InputMode == inputModeOTA {
		if err := d.ensureOTAPayloadFilesystems(); err != nil {
			return fmt.Errorf("diff: parseLaunchdPlists: %v", err)
		}
		oldConfig, err := launchdConfigFromRoots(otaLaunchdSearchRoots(&d.Old))
		if err != nil {
			return fmt.Errorf("diff: parseLaunchdPlists: failed to get 'Old' launchd config: %v", err)
		}
		newConfig, err := launchdConfigFromRoots(otaLaunchdSearchRoots(&d.New))
		if err != nil {
			return fmt.Errorf("diff: parseLaunchdPlists: failed to get 'New' launchd config: %v", err)
		}
		return d.applyLaunchdGitDiff(oldConfig, newConfig)
	}
	if d.Old.InputMode != inputModeIPSW {
		return fmt.Errorf("diff: parseLaunchdPlists: launchd diff is only supported for IPSW and OTA payload inputs")
	}
	return fmt.Errorf("diff: parseLaunchdPlists: IPSW mode uses launchdJob via the volume-major orchestrator")
}

// applyLaunchdGitDiff renders the git diff of the two extracted launchd
// __TEXT.__config strings into d.Launchd. Shared by parseLaunchdPlists
// (OTA) and launchdJob (IPSW).
func (d *Diff) applyLaunchdGitDiff(oldConfig, newConfig string) error {
	out, err := utils.GitDiff(
		oldConfig+"\n",
		newConfig+"\n",
		&utils.GitDiffConfig{Color: false, Tool: "git"})
	if err != nil {
		return err
	}
	if len(out) > 0 {
		d.Launchd = "```diff\n" + out + "\n```"
	}
	return nil
}

func (d *Diff) parseFirmwares() (err error) {
	conf := &mcmd.DiffConfig{
		Markdown:   true,
		Color:      false,
		DiffTool:   "git",
		AllowList:  d.conf.AllowList,
		BlockList:  d.conf.BlockList,
		CStrings:   d.conf.CStrings,
		FuncStarts: d.conf.FuncStarts,
		Verbose:    d.conf.Verbose,
	}
	if d.Old.InputMode == inputModeOTA {
		d.Firmwares, err = diffFirmwaresFromOTA(&d.Old, &d.New, conf)
		return
	}
	if d.Old.InputMode == inputModeDirectory {
		log.Warn("Firmware diff (--fw) not supported for directory inputs; skipping")
		return nil
	}
	d.Firmwares, err = mcmd.DiffFirmwares(d.Old.IPSWPath, d.New.IPSWPath, conf)
	return
}

func (d *Diff) parseIBoot() (err error) {
	d.IBoot = &IBootDiff{
		New:     make(map[string][]string),
		Removed: make(map[string][]string),
	}
	var oldIBoot, newIBoot *iboot.IBoot
	if d.Old.InputMode == inputModeOTA {
		oldIBoot, err = parseOTAIBoot(&d.Old)
		if err != nil {
			return fmt.Errorf("failed to get iBoot from 'Old' OTA: %v", err)
		}
		newIBoot, err = parseOTAIBoot(&d.New)
		if err != nil {
			return fmt.Errorf("failed to get iBoot from 'New' OTA: %v", err)
		}
	} else {
		tmpDIR, err := os.MkdirTemp("", "ipsw_extract_iboot")
		if err != nil {
			return fmt.Errorf("failed to create temporary directory to store im4ps: %v", err)
		}
		defer os.RemoveAll(tmpDIR)
		getIboot := func(ipswPath string) (*iboot.IBoot, error) {
			iBootIm4ps, err := utils.Unzip(ipswPath, tmpDIR, func(f *zip.File) bool {
				// return regexp.MustCompile(`iBSS.*\.im4p$`).MatchString(f.Name) || regexp.MustCompile(`iBoot\..*\.im4p$`).MatchString(f.Name)
				return regexp.MustCompile(`iBoot\..*\.im4p$`).MatchString(f.Name)
			})
			if err != nil {
				return nil, fmt.Errorf("failed to unzip iBoot im4p: %v", err)
			}
			im4p, err := img4.OpenPayload(iBootIm4ps[0])
			if err != nil {
				return nil, fmt.Errorf("failed to open im4p: %v", err)
			}
			return iboot.Parse(im4p.Data)
		}
		oldIBoot, err = getIboot(d.Old.IPSWPath)
		if err != nil {
			return fmt.Errorf("failed to get iBoot from 'Old' IPSW: %v", err)
		}
		newIBoot, err = getIboot(d.New.IPSWPath)
		if err != nil {
			return fmt.Errorf("failed to get iBoot from 'New' IPSW: %v", err)
		}
	}
	d.IBoot.Versions = []string{oldIBoot.Version, newIBoot.Version}
	for name, strs := range newIBoot.Strings {
		if _, ok := oldIBoot.Strings[name]; ok {
			for _, str := range strs {
				if len(str) < 10 {
					continue
				}
				found := false
				for _, oldStr := range oldIBoot.Strings[name] {
					if str == oldStr {
						found = true
						break
					}
				}
				if !found {
					d.IBoot.New[name] = append(d.IBoot.New[name], str)
				}
			}
		} else {
			for _, str := range strs {
				d.IBoot.New[name] = append(d.IBoot.New[name], str)
			}
		}
	}
	for name, strs := range oldIBoot.Strings {
		if _, ok := newIBoot.Strings[name]; ok {
			for _, str := range strs {
				if len(str) < 10 {
					continue
				}
				found := false
				for _, newStr := range newIBoot.Strings[name] {
					if str == newStr {
						found = true
						break
					}
				}
				if !found {
					d.IBoot.Removed[name] = append(d.IBoot.Removed[name], str)
				}
			}
		}
	}
	return nil
}

// parseFeatureFlags handles OTA and Directory input modes. IPSW mode is
// handled by featuresJob via the volume-major orchestrator.
func (d *Diff) parseFeatureFlags() error {
	var oldMounts, newMounts map[string]mount
	switch d.Old.InputMode {
	case inputModeOTA:
		if err := d.ensureOTAPayloadFilesystems(); err != nil {
			return err
		}
		oldMounts = otaDiffMounts(&d.Old)
		newMounts = otaDiffMounts(&d.New)
	case inputModeDirectory:
		oldMounts = d.Old.Mount
		newMounts = d.New.Mount
	default:
		return fmt.Errorf("diff: parseFeatureFlags: IPSW mode uses featuresJob via the volume-major orchestrator")
	}

	prevByVolume := make(map[string]map[string]string)
	nextByVolume := make(map[string]map[string]string)
	volumes, err := collectFeatureFlagsByVolume(oldMounts, prevByVolume, newMounts, nextByVolume)
	if err != nil {
		return err
	}
	out, err := buildPlistDiffByVolume(volumes, prevByVolume, nextByVolume)
	if err != nil {
		return err
	}
	d.Features = out
	return nil
}

// collectFeatureFlagsByVolume walks System/Library/FeatureFlags under every
// mount on both sides, populating per-volume plist maps. Returns the union
// of volume names in sorted order so callers can build a deterministic
// output.
func collectFeatureFlagsByVolume(oldMounts map[string]mount, prev map[string]map[string]string, newMounts map[string]mount, next map[string]map[string]string) ([]string, error) {
	names := unionMountNames(oldMounts, newMounts)
	for _, name := range names {
		if mnt, ok := oldMounts[name]; ok {
			prev[name] = make(map[string]string)
			if err := collectFeatureFlagsFromMount(mnt.MountPath, name, prev[name]); err != nil {
				return nil, err
			}
		}
		if mnt, ok := newMounts[name]; ok {
			next[name] = make(map[string]string)
			if err := collectFeatureFlagsFromMount(mnt.MountPath, name, next[name]); err != nil {
				return nil, err
			}
		}
	}
	return names, nil
}

// trackVolumeOnce appends label to volumes if not already present.
func trackVolumeOnce(volumes *[]string, label string) {
	if slices.Contains(*volumes, label) {
		return
	}
	*volumes = append(*volumes, label)
}

func removeVolume(volumes *[]string, label string) {
	out := (*volumes)[:0]
	for _, v := range *volumes {
		if v != label {
			out = append(out, v)
		}
	}
	*volumes = out
}

// buildPlistDiffByVolume builds the per-volume PlistDiff map. Empty
// per-volume diffs are omitted. Shared by featuresJob and locsJob.
func buildPlistDiffByVolume(volumes []string, prev, next map[string]map[string]string) (map[string]*PlistDiff, error) {
	out := make(map[string]*PlistDiff, len(volumes))
	for _, vol := range volumes {
		diff, err := buildPlistDiff(prev[vol], next[vol])
		if err != nil {
			return nil, err
		}
		if plistDiffHasContent(diff) {
			out[vol] = diff
		}
	}
	return out, nil
}

func plistDiffHasContent(d *PlistDiff) bool {
	return d != nil && (len(d.New) > 0 || len(d.Removed) > 0 || len(d.Updated) > 0)
}

// buildPlistDiff computes a PlistDiff from path-keyed old/new plist content
// maps. Shared by feature-flag and localization paths.
func buildPlistDiff(oldPlists, newPlists map[string]string) (*PlistDiff, error) {
	diff := &PlistDiff{
		New:     make(map[string]string),
		Updated: make(map[string]string),
	}

	prevFiles := make([]string, 0, len(oldPlists))
	for f := range oldPlists {
		prevFiles = append(prevFiles, f)
	}
	slices.Sort(prevFiles)

	nextFiles := make([]string, 0, len(newPlists))
	for f := range newPlists {
		nextFiles = append(nextFiles, f)
	}
	slices.Sort(nextFiles)

	newFiles := utils.Difference(nextFiles, prevFiles)
	diff.Removed = utils.Difference(prevFiles, nextFiles)

	for _, f2 := range nextFiles {
		dat2 := newPlists[f2]
		if slices.Contains(newFiles, f2) {
			diff.New[f2] = dat2
			continue
		}
		dat1, ok := oldPlists[f2]
		if !ok || strings.EqualFold(dat2, dat1) {
			continue
		}
		out, err := utils.GitDiff(dat1+"\n", dat2+"\n", &utils.GitDiffConfig{Color: false, Tool: "git"})
		if err != nil {
			return nil, err
		}
		if len(out) == 0 {
			continue
		}
		diff.Updated[f2] = "```diff\n" + out + "\n```\n"
	}

	return diff, nil
}

// parseFiles diffs file paths for OTA and Directory input modes. IPSW mode
// is handled by filesJob via the volume-major orchestrator.
func (d *Diff) parseFiles() error {
	if d.Old.InputMode == inputModeOTA {
		if err := d.ensureOTAPayloadFilesystems(); err != nil {
			return err
		}
		var err error
		d.Files, err = diffFilesInMounts(otaDiffMounts(&d.Old), otaDiffMounts(&d.New))
		return err
	}
	if d.Old.InputMode == inputModeDirectory {
		var err error
		d.Files, err = diffFilesInMounts(d.Old.Mount, d.New.Mount)
		return err
	}
	return fmt.Errorf("diff: parseFiles: IPSW mode uses filesJob via the volume-major orchestrator")
}

// openCacheStore initializes the persistent cache store for IPSW-mode runs
// and installs it on d via SetStore. Non-IPSW input modes are returned a nil
// cleanup so the per-orchestrator MemoryStore path stays in effect; failures
// to open the persistent store are logged and fall back to a temp-backed
// SQLiteStore via storage.OpenCacheStore.
func (d *Diff) openCacheStore() func() {
	if d.conf == nil {
		return nil
	}
	if d.Old.InputMode != inputModeIPSW || d.New.InputMode != inputModeIPSW {
		return nil
	}
	opts := storage.CacheOptions{
		OldInfo:  d.Old.Info,
		NewInfo:  d.New.Info,
		Dir:      d.conf.Cache.Dir,
		NoCache:  d.conf.Cache.NoCache,
		Clean:    d.conf.Cache.Clean,
		MaxBytes: d.conf.Cache.MaxBytes,
	}
	store, cleanup, err := storage.OpenCacheStore(opts)
	if err != nil {
		log.WithError(err).Warn("failed to open diff cache; falling back to in-memory store")
		return nil
	}
	if d.conf.Cache.NoCache {
		log.Debug("using temporary diff cache (--no-cache)")
	} else if path, ok := persistentCachePath(d.Old.Info, d.New.Info, d.conf.Cache.Dir); ok {
		log.Infof("using diff cache at %s", path)
	} else {
		log.Debug("using temporary diff cache (identity unavailable)")
	}
	d.SetStore(store)
	return func() {
		cleanup()
		d.SetStore(nil)
	}
}

// persistentCachePath returns the path OpenCacheStore would resolve for the
// (old, new) pair given the override directory, so callers can log the
// concrete path. ok=false when either Info lacks a BuildManifest and the
// cache must therefore fall back to a temp-backed store.
func persistentCachePath(oldInfo, newInfo *info.Info, dir string) (string, bool) {
	oldID, err := storage.IPSWCacheIdentity(oldInfo)
	if err != nil {
		return "", false
	}
	newID, err := storage.IPSWCacheIdentity(newInfo)
	if err != nil {
		return "", false
	}
	path, err := storage.ResolveCachePath(oldID, newID, dir)
	if err != nil {
		return "", false
	}
	return path, true
}
