package diff

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
)

var localizationOwnerExtensions = [...]string{
	".assistantbundle",
	".syncbundle",
	".axuiservice",
	".axbundle",
	".framework",
	".migrator",
	".imservice",
	".appex",
	".bundle",
	".driver",
	".plugin",
	".dext",
	".kext",
	".app",
	".xpc",
	".fs",
}

// parseLocalizations handles OTA and Directory input modes. IPSW mode is
// handled by locsJob via the volume-major orchestrator.
func (d *Diff) parseLocalizations() error {
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
		return fmt.Errorf("diff: parseLocalizations: IPSW mode uses locsJob via the volume-major orchestrator")
	}

	prevByVolume := make(map[string]map[string]string)
	nextByVolume := make(map[string]map[string]string)
	names := unionMountNames(oldMounts, newMounts)
	for _, name := range names {
		if mnt, ok := oldMounts[name]; ok {
			prevByVolume[name] = make(map[string]string)
			if err := collectLocalizedResourcesFromMount(mnt.MountPath, name, prevByVolume[name]); err != nil {
				return err
			}
		}
		if mnt, ok := newMounts[name]; ok {
			nextByVolume[name] = make(map[string]string)
			if err := collectLocalizedResourcesFromMount(mnt.MountPath, name, nextByVolume[name]); err != nil {
				return err
			}
		}
	}

	out, err := assembleLocalizationDiffByVolume(names, prevByVolume, nextByVolume)
	if err != nil {
		return err
	}
	d.Localizations = out
	return nil
}

// assembleLocalizationDiffByVolume produces the per-volume PlistDiff map
// for localizations. Empty per-volume diffs are omitted. Shared by
// parseLocalizations (OTA/Directory) and locsJob (IPSW).
func assembleLocalizationDiffByVolume(volumes []string, prev, next map[string]map[string]string) (map[string]*PlistDiff, error) {
	out := make(map[string]*PlistDiff)
	for _, vol := range volumes {
		diff := &PlistDiff{
			New:     make(map[string]string),
			Updated: make(map[string]string),
		}
		if err := diffLocalizedResources(diff, prev[vol], next[vol]); err != nil {
			return nil, err
		}
		if plistDiffHasContent(diff) {
			out[vol] = diff
		}
	}
	return out, nil
}

// collectLocalizedResourcesFromMount walks a single mount root for
// localization resources, populating out keyed by the resource path.
func collectLocalizedResourcesFromMount(mountPath, volumeLabel string, out map[string]string) error {
	return walkFolderFiles(mountPath, func(_ string, absPath string) error {
		return collectLocalizedResourceFile(out, volumeLabel, mountPath, absPath)
	})
}

func collectLocalizedResourceFile(out map[string]string, mountName, mountPoint, absPath string) error {
	if !isLocalizedResourcePath(absPath) {
		return nil
	}
	if !isUSEnglishLocalizedResourcePath(absPath) {
		return nil
	}

	content, err := normalizeLocalizedResource(absPath)
	if err != nil {
		log.Debugf("skipping localization resource %s: %v", absPath, err)
		return nil
	}
	if content == "" {
		return nil
	}

	relPath := relativeToRoot(mountPoint, absPath)
	key := filepath.ToSlash(filepath.Join(mountName, relPath))
	out[key] = content
	return nil
}

func isLocalizedResourcePath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".loctable", ".strings", ".stringsdict":
		return true
	default:
		return false
	}
}

func normalizeLocalizedResource(path string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("failed to read resource: %w", err)
	}

	var decoded map[string]any
	if _, err := plist.Unmarshal(data, &decoded); err != nil {
		return "", fmt.Errorf("failed to decode plist resource: %w", err)
	}
	if strings.EqualFold(filepath.Ext(path), ".loctable") {
		decoded = filterUSEnglishLocalizationTable(decoded)
		if len(decoded) == 0 {
			return "", nil
		}
	}

	var lines []string
	flattenLocalizedValue("", decoded, &lines)
	slices.Sort(lines)
	return strings.Join(lines, "\n"), nil
}

func isUSEnglishLocalizedResourcePath(path string) bool {
	locale, ok := lprojLocale(path)
	if !ok {
		return true
	}
	return isUSEnglishLproj(locale)
}

func lprojLocale(path string) (string, bool) {
	for part := range strings.SplitSeq(filepath.ToSlash(path), "/") {
		lower := strings.ToLower(part)
		if strings.HasSuffix(lower, ".lproj") {
			return part[:len(part)-len(".lproj")], true
		}
	}
	return "", false
}

func isUSEnglishLproj(locale string) bool {
	if strings.EqualFold(locale, "base") {
		return true
	}
	return isUSEnglishLocale(locale)
}

func filterUSEnglishLocalizationTable(values map[string]any) map[string]any {
	if locale, ok := preferredEnglishLocale(values); ok {
		return map[string]any{"en": values[locale]}
	}
	return map[string]any{}
}

func isUSEnglishLocale(locale string) bool {
	switch normalizeLocale(locale) {
	case "en", "en_us":
		return true
	default:
		return false
	}
}

func preferredEnglishLocale(values map[string]any) (string, bool) {
	var locales []string
	for locale := range values {
		if isEnglishLocale(locale) {
			locales = append(locales, locale)
		}
	}
	if len(locales) == 0 {
		return "", false
	}

	sortLocales(locales)
	for _, preferred := range [...]string{"en_us", "en"} {
		for _, locale := range locales {
			if normalizeLocale(locale) == preferred {
				return locale, true
			}
		}
	}
	return locales[0], true
}

func isEnglishLocale(locale string) bool {
	normalized := normalizeLocale(locale)
	return normalized == "en" || strings.HasPrefix(normalized, "en_")
}

func normalizeLocale(locale string) string {
	return strings.ToLower(strings.ReplaceAll(locale, "-", "_"))
}

func sortLocales(locales []string) {
	slices.SortFunc(locales, func(a, b string) int {
		if cmp := strings.Compare(normalizeLocale(a), normalizeLocale(b)); cmp != 0 {
			return cmp
		}
		return strings.Compare(a, b)
	})
}

func flattenLocalizedValue(prefix string, value any, lines *[]string) {
	switch typed := value.(type) {
	case nil:
		appendLocalizedLine(prefix, nil, lines)
	case map[string]any:
		flattenLocalizedMap(prefix, typed, lines)
	case []any:
		flattenLocalizedList(prefix, typed, lines)
	default:
		appendLocalizedLine(prefix, value, lines)
	}
}

func flattenLocalizedMap(prefix string, values map[string]any, lines *[]string) {
	if len(values) == 0 {
		appendLocalizedLine(prefix, map[string]any{}, lines)
		return
	}

	for _, key := range slices.Sorted(maps.Keys(values)) {
		flattenLocalizedValue(joinLocalizedPath(prefix, key), values[key], lines)
	}
}

func flattenLocalizedList(prefix string, values []any, lines *[]string) {
	if len(values) == 0 {
		appendLocalizedLine(prefix, []any{}, lines)
		return
	}

	for idx, value := range values {
		flattenLocalizedValue(fmt.Sprintf("%s[%d]", prefix, idx), value, lines)
	}
}

func joinLocalizedPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func appendLocalizedLine(prefix string, value any, lines *[]string) {
	if prefix == "" {
		prefix = "$"
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		encoded = fmt.Appendf(nil, "%q", fmt.Sprint(value))
	}
	*lines = append(*lines, fmt.Sprintf("%s = %s", prefix, encoded))
}

func localizationDisplayName(path string) string {
	if owner := localizationOwnerName(path); owner != "" {
		return owner
	}

	base := filepath.Base(path)
	ext := filepath.Ext(base)
	if ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	if base == "" || base == "." {
		return "localization"
	}
	return base
}

func localizationOwnerName(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for idx := len(parts) - 2; idx >= 0; idx-- {
		part := parts[idx]
		if strings.HasSuffix(strings.ToLower(part), ".lproj") {
			continue
		}
		if owner, ok := trimLocalizationOwnerExtension(part); ok {
			return owner
		}
	}
	return ""
}

func trimLocalizationOwnerExtension(name string) (string, bool) {
	lower := strings.ToLower(name)
	for _, ext := range localizationOwnerExtensions {
		if strings.HasSuffix(lower, ext) {
			trimmed := name[:len(name)-len(ext)]
			if trimmed == "" {
				break
			}
			return trimmed, true
		}
	}
	return "", false
}

func diffLocalizedResources(out *PlistDiff, oldResources, newResources map[string]string) error {
	prevFiles := sortedLocalizationPaths(oldResources)
	nextFiles := sortedLocalizationPaths(newResources)

	newFiles := utils.Difference(nextFiles, prevFiles)
	out.Removed = utils.Difference(prevFiles, nextFiles)
	slices.Sort(out.Removed)

	newFileSet := make(map[string]struct{}, len(newFiles))
	for _, path := range newFiles {
		newFileSet[path] = struct{}{}
	}

	for _, path := range nextFiles {
		nextContent := newResources[path]
		if _, ok := newFileSet[path]; ok {
			out.New[path] = nextContent
			continue
		}

		prevContent, ok := oldResources[path]
		if !ok || nextContent == prevContent {
			continue
		}

		diff, err := utils.GitDiff(prevContent+"\n", nextContent+"\n", &utils.GitDiffConfig{Color: false, Tool: "git"})
		if err != nil {
			return err
		}
		if diff == "" {
			continue
		}
		out.Updated[path] = "```diff\n" + diff + "\n```\n"
	}

	return nil
}

func sortedLocalizationPaths(resources map[string]string) []string {
	return slices.Sorted(maps.Keys(resources))
}
