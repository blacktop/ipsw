package diff

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
)

type inputMode uint8

const (
	inputModeIPSW inputMode = iota
	inputModeDirectory
	inputModeOTA
)

var directoryInputDMGNames = []string{"SystemOS", "AppOS", "FileSystem", "ExclaveOS"}

func configureDirectoryContext(ctx *Context) {
	ctx.Version = "Patched OTA"
	ctx.Build = filepath.Base(ctx.IPSWPath)
	ctx.Folder = filepath.Clean(ctx.IPSWPath)
}

func detectInputMode(oldPath, newPath string) (inputMode, error) {
	oldIsDir, err := isDirectory(oldPath)
	if err != nil {
		return inputModeIPSW, fmt.Errorf("failed to stat old input: %w", err)
	}
	newIsDir, err := isDirectory(newPath)
	if err != nil {
		return inputModeIPSW, fmt.Errorf("failed to stat new input: %w", err)
	}
	if oldIsDir != newIsDir {
		return inputModeIPSW, fmt.Errorf("inputs must both be IPSW files or both be directories of patched OTA DMGs")
	}
	if oldIsDir {
		return inputModeDirectory, nil
	}
	return inputModeIPSW, nil
}

func isDirectory(path string) (bool, error) {
	info, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

// unsupportedFlagsForDirectoryMode returns CLI flag names that are
// not fully supported when diffing pre-patched directory inputs.
// These flags are skipped with a warning instead of hard-erroring.
func unsupportedFlagsForDirectoryMode(conf *Config) []string {
	var unsupported []string
	if conf.LaunchD {
		unsupported = append(unsupported, "--launchd")
	}
	if conf.Sandbox {
		unsupported = append(unsupported, "--sandbox")
	}
	return unsupported
}

func findDirectoryInputDMGs(root string) (map[string]string, error) {
	root = filepath.Clean(root)
	found := make(map[string]string)

	for _, name := range directoryInputDMGNames {
		var matches []string
		for _, pattern := range []string{"*.dmg", "*.dmg.aea", "*.aea"} {
			hits, err := filepath.Glob(filepath.Join(root, name, pattern))
			if err != nil {
				return nil, fmt.Errorf("failed to glob %s DMGs: %w", name, err)
			}
			matches = append(matches, hits...)
		}
		sort.Strings(matches)
		matches = slices.Compact(matches)
		switch len(matches) {
		case 0:
			continue
		case 1:
			found[name] = matches[0]
		default:
			return nil, fmt.Errorf("found too many %s DMGs in %s", name, root)
		}
	}

	if len(found) == 0 {
		return nil, fmt.Errorf("no DMGs found under %s", root)
	}

	return found, nil
}

func mountDirectoryDMGs(ctx *Context) error {
	dmgs, err := findDirectoryInputDMGs(ctx.IPSWPath)
	if err != nil {
		return err
	}

	if _, ok := dmgs["SystemOS"]; !ok {
		return fmt.Errorf("directory input %s is missing a SystemOS DMG", ctx.IPSWPath)
	}

	names := make([]string, 0, len(dmgs))
	for name := range dmgs {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		log.Infof("Mounting %s DMG", name)
		mnt, err := mountNamedDMG(name, dmgs[name], ctx.PemDB)
		if err != nil {
			releaseDirectoryMounts(ctx.Build, ctx.Mount)
			return err
		}
		ctx.Mount[name] = mnt
		if name == "SystemOS" {
			ctx.SystemOsDmgPath = mnt.DmgPath
			ctx.MountPath = mnt.MountPath
			ctx.IsMounted = mnt.IsMounted
		}
	}

	return nil
}

func releaseDirectoryMounts(label string, mounts map[string]mount) {
	if label == "" {
		label = "Directory"
	}
	for _, name := range sortedMountNames(mounts) {
		mnt := mounts[name]
		if mnt.IsMounted {
			utils.Indent(log.Info, 2)(fmt.Sprintf("Leaving '%s' %s DMG mounted", label, name))
			mnt.cleanup()
			continue
		}
		utils.Indent(log.Info, 2)(fmt.Sprintf("Unmounting '%s' %s DMG", label, name))
		if err := utils.Retry(3, 2*time.Second, func() error {
			return utils.Unmount(mnt.MountPath, true)
		}); err != nil {
			utils.Indent(log.Error, 3)(fmt.Sprintf("failed to unmount '%s' %s DMG: %v", label, name, err))
		}
		mnt.cleanup()
	}
}

func mountNamedDMG(name, path, pemDB string) (mount, error) {
	mnt := mount{
		DmgPath: filepath.Clean(path),
	}

	if filepath.Ext(mnt.DmgPath) == ".aea" {
		tmpDir, err := os.MkdirTemp("", "ipsw-diff-dmg")
		if err != nil {
			return mnt, fmt.Errorf("failed to create temp dir for %s decryption: %w", name, err)
		}
		decryptedPath, err := aea.Decrypt(&aea.DecryptConfig{
			Input:    mnt.DmgPath,
			Output:   tmpDir,
			PemDB:    pemDB,
			Proxy:    "",
			Insecure: false,
		})
		if err != nil {
			_ = os.Remove(tmpDir)
			return mnt, fmt.Errorf("failed to decrypt %s DMG: %w", name, err)
		}
		mnt.DmgPath = decryptedPath
		mnt.CleanupPaths = []string{decryptedPath, tmpDir}
	}

	utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting %s", mnt.DmgPath))
	mountPoint, alreadyMounted, err := utils.MountDMG(mnt.DmgPath, "")
	if err != nil {
		mnt.cleanup()
		return mnt, fmt.Errorf("failed to mount %s DMG: %w", name, err)
	}
	mnt.MountPath = mountPoint
	mnt.IsMounted = alreadyMounted
	if alreadyMounted {
		utils.Indent(log.Info, 3)(fmt.Sprintf("%s already mounted", mnt.DmgPath))
	}

	return mnt, nil
}

func (m mount) cleanup() {
	for _, path := range m.CleanupPaths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			utils.Indent(log.Warn, 3)(fmt.Sprintf("failed to remove %s: %v", path, err))
		}
	}
}

func relativeToRoot(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	if _, rest, ok := strings.Cut(path, root); ok {
		return filepath.ToSlash(strings.TrimPrefix(rest, string(os.PathSeparator)))
	}
	return filepath.ToSlash(filepath.Base(path))
}

func walkFolderFiles(root string, fn func(relPath, absPath string) error) error {
	return search.WalkFilesInRoot(root, func(absPath string) error {
		return fn(relativeToRoot(root, absPath), absPath)
	})
}

// diffMachosInMounts diffs Mach-Os per volume between the old and new mount
// sets. Each volume's contents are diffed independently, producing a per-
// volume map matching the IPSW machosJob output shape so renderers and JSON
// consumers see the same structure across input modes.
func diffMachosInMounts(oldMounts, newMounts map[string]mount, conf *mcmd.DiffConfig) (map[string]*mcmd.MachoDiff, error) {
	out := make(map[string]*mcmd.MachoDiff)

	names := unionMountNames(oldMounts, newMounts)
	for _, name := range names {
		prev := make(map[string]*mcmd.DiffInfo)
		if mnt, ok := oldMounts[name]; ok {
			if err := search.ForEachMacho(mnt.MountPath, func(path string, m *macho.File) error {
				key := filepath.ToSlash(relativeToRoot(mnt.MountPath, path))
				prev[key] = mcmd.GenerateDiffInfo(m, conf)
				return nil
			}); err != nil {
				return nil, fmt.Errorf("failed to parse machos in old %s mount: %w", name, err)
			}
		}

		next := make(map[string]*mcmd.DiffInfo)
		if mnt, ok := newMounts[name]; ok {
			if err := search.ForEachMacho(mnt.MountPath, func(path string, m *macho.File) error {
				key := filepath.ToSlash(relativeToRoot(mnt.MountPath, path))
				next[key] = mcmd.GenerateDiffInfo(m, conf)
				return nil
			}); err != nil {
				return nil, fmt.Errorf("failed to parse machos in new %s mount: %w", name, err)
			}
		}

		if len(prev) == 0 && len(next) == 0 {
			continue
		}
		diff := &mcmd.MachoDiff{Updated: make(map[string]string)}
		if err := diff.Generate(prev, next, conf); err != nil {
			return nil, fmt.Errorf("failed to generate %s machos diff: %w", name, err)
		}
		if machoDiffHasContent(diff) {
			out[name] = diff
		}
	}

	return out, nil
}

// unionMountNames returns the sorted union of two mount maps' keys.
func unionMountNames(a, b map[string]mount) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for name := range a {
		seen[name] = struct{}{}
	}
	for name := range b {
		seen[name] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func diffFilesInMounts(oldMounts, newMounts map[string]mount) (*FileDiff, error) {
	out := &FileDiff{
		New:     make(map[string][]string),
		Removed: make(map[string][]string),
	}

	prev, err := collectFilesInMounts(oldMounts)
	if err != nil {
		return nil, err
	}
	next, err := collectFilesInMounts(newMounts)
	if err != nil {
		return nil, err
	}

	dmgNames := make([]string, 0, len(prev))
	for name := range prev {
		dmgNames = append(dmgNames, name)
	}
	for name := range next {
		if !slices.Contains(dmgNames, name) {
			dmgNames = append(dmgNames, name)
		}
	}
	sort.Strings(dmgNames)

	for _, name := range dmgNames {
		out.New[name] = utils.Difference(next[name], prev[name])
		out.Removed[name] = utils.Difference(prev[name], next[name])
		sort.Strings(out.New[name])
		sort.Strings(out.Removed[name])
	}

	return out, nil
}

func collectFilesInMounts(mounts map[string]mount) (map[string][]string, error) {
	out := make(map[string][]string)
	for _, name := range sortedMountNames(mounts) {
		mnt := mounts[name]
		if err := walkFolderFiles(mnt.MountPath, func(relPath, _ string) error {
			out[name] = append(out[name], filepath.ToSlash(relPath))
			return nil
		}); err != nil {
			return nil, fmt.Errorf("failed to walk %s mount: %w", name, err)
		}
		sort.Strings(out[name])
	}
	return out, nil
}

func sortedMountNames(mounts map[string]mount) []string {
	names := make([]string, 0, len(mounts))
	for name := range mounts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
