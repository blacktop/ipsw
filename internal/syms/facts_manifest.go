package syms

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

const (
	factsCollectionSchemaVersionV1 uint32 = 1
	factsCollectionSchemaVersionV2 uint32 = 2
	factsCollectionSchemaVersionV3 uint32 = 3
)

type factsSourceIdentity struct {
	Name                      string   `json:"name"`
	LegacySHA1                string   `json:"legacy_sha1"`
	SHA256                    string   `json:"sha256"`
	Length                    int64    `json:"length"`
	ConsistencyChecks         []string `json:"consistency_checks"`
	ImmutableSourceAssumption string   `json:"immutable_source_assumption"`
}

type sourceSnapshot struct {
	info os.FileInfo
}

func readFactsSource(path string) (factsSourceIdentity, *sourceSnapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return factsSourceIdentity{}, nil, err
	}
	defer f.Close()

	before, err := f.Stat()
	if err != nil {
		return factsSourceIdentity{}, nil, err
	}
	sha1Hash, sha256Hash := sha1.New(), sha256.New()
	n, err := io.Copy(io.MultiWriter(sha1Hash, sha256Hash), f)
	if err != nil {
		return factsSourceIdentity{}, nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return factsSourceIdentity{}, nil, err
	}
	if !os.SameFile(before, after) || n != before.Size() || n != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return factsSourceIdentity{}, nil, fmt.Errorf("source changed while calculating identity")
	}
	return factsSourceIdentity{
		Name:       filepath.Base(path),
		LegacySHA1: hex.EncodeToString(sha1Hash.Sum(nil)),
		SHA256:     hex.EncodeToString(sha256Hash.Sum(nil)),
		Length:     n,
		ConsistencyChecks: []string{
			"same_file", "size", "modification_time",
		},
		ImmutableSourceAssumption: "source bytes do not change without a detectable file identity, size, or modification-time change",
	}, &sourceSnapshot{info: after}, nil
}

func (s *sourceSnapshot) validate(path string) error {
	current, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to recheck source: %w", err)
	}
	if !os.SameFile(s.info, current) || s.info.Size() != current.Size() || !s.info.ModTime().Equal(current.ModTime()) {
		return fmt.Errorf("source identity, size, or modification time changed during scan")
	}
	return nil
}

type factsManifestComponent struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type factsManifestIdentity struct {
	Device          string                   `json:"device,omitempty"`
	Board           string                   `json:"board,omitempty"`
	Variant         string                   `json:"variant,omitempty"`
	RestoreBehavior string                   `json:"restore_behavior,omitempty"`
	Components      []factsManifestComponent `json:"components"`
}

type factsManifestSelection struct {
	RequestedSelector string                  `json:"requested_selector,omitempty"`
	Devices           []string                `json:"devices"`
	Boards            []string                `json:"boards"`
	Identities        []factsManifestIdentity `json:"identities"`
}

type factsRequestedScope struct {
	Family  string   `json:"family"`
	Volumes []string `json:"volumes"`
}

type factsCoverage struct {
	Family           string                  `json:"family"`
	Volume           string                  `json:"volume"`
	RecordVolume     string                  `json:"record_volume,omitempty"`
	Status           string                  `json:"status"`
	Reason           string                  `json:"reason,omitempty"`
	ComponentPaths   []string                `json:"component_paths,omitempty"`
	AliasOf          string                  `json:"alias_of,omitempty"`
	Records          uint64                  `json:"records"`
	ComponentRecords []factsComponentRecords `json:"component_records,omitempty"`
}

type factsComponentRecords struct {
	Path    string `json:"path"`
	Records uint64 `json:"records"`
}

// The namespace distinguishes variants, not the hardware suffix in the exact
// source path. Unknown naming schemes need an explicit policy before matching.
func kernelFactsNamespace(component string) (string, error) {
	name := filepath.Base(component)
	for _, variant := range []string{"release", "research"} {
		prefix := "kernelcache." + variant
		if name == prefix || strings.HasPrefix(name, prefix+".") {
			return "kernelcache/" + variant, nil
		}
	}
	return "", fmt.Errorf("unsupported kernelcache component variant: %q", component)
}

type factsCollectionStartLine struct {
	Type                    string                 `json:"type"`
	CollectionSchemaVersion uint32                 `json:"collection_schema_version"`
	CollectionID            string                 `json:"collection_id"`
	Source                  factsSourceIdentity    `json:"source"`
	Selection               factsManifestSelection `json:"selection"`
	Requested               []factsRequestedScope  `json:"requested"`
}

type comparisonFactsCompleteLine struct {
	Type                          string          `json:"type"`
	CollectionSchemaVersion       uint32          `json:"collection_schema_version"`
	CollectionID                  string          `json:"collection_id"`
	Status                        string          `json:"status"`
	RequiresSuccessfulProcessExit bool            `json:"requires_successful_process_exit"`
	Records                       uint64          `json:"records"`
	RecordsSHA256                 string          `json:"records_sha256"`
	Coverage                      []factsCoverage `json:"coverage"`
}

type factsCollection struct {
	start    factsCollectionStartLine
	coverage []factsCoverage
}

var manifestComponentNames = []string{
	"Ap,ExclaveOS", "Cryptex1,AppOS", "Cryptex1,SystemOS", "KernelCache", "OS",
}

func manifestPath(component plist.IdentityManifest) (string, bool) {
	path, ok := component.Info["Path"].(string)
	return path, ok && path != ""
}

func newFactsCollection(cfg *JSONLConfig, inf *info.Info, source factsSourceIdentity) (*factsCollection, error) {
	selection := factsSelection(cfg.Device, inf)
	requested := requestedFactsScopes(cfg)
	version := factsCollectionSchemaVersionV1
	if cfg.FileSystem {
		version = factsCollectionSchemaVersionV2
	}
	if cfg.Kernel {
		version = factsCollectionSchemaVersionV3
		components := componentPaths(selection, "KernelCache")
		if len(components) == 0 {
			if cfg.Device == "" {
				return nil, fmt.Errorf("IPSW %s has no BuildManifest KernelCache component paths", filepath.Base(cfg.IPSW))
			}
			return nil, fmt.Errorf("device %q has no BuildManifest KernelCache component paths", cfg.Device)
		}
		for _, component := range components {
			if _, err := kernelFactsNamespace(component); err != nil {
				return nil, err
			}
		}
	}
	collectionID, err := factsCollectionID(version, source, selection, requested)
	if err != nil {
		return nil, err
	}
	c := &factsCollection{
		start: factsCollectionStartLine{
			Type:                    "comparison_facts_collection_start",
			CollectionSchemaVersion: version,
			CollectionID:            collectionID,
			Source:                  source,
			Selection:               selection,
			Requested:               requested,
		},
	}
	c.coverage = initialFactsCoverage(cfg, selection)
	return c, nil
}

func factsSelection(requested string, inf *info.Info) factsManifestSelection {
	selection := factsManifestSelection{RequestedSelector: requested}
	for _, bi := range inf.Plists.BuildIdentities {
		device := bi.ApProductType
		if device == "" && len(inf.Plists.BuildManifest.SupportedProductTypes) == 1 {
			device = inf.Plists.BuildManifest.SupportedProductTypes[0]
		}
		identity := factsManifestIdentity{
			Device: device, Board: bi.Info.DeviceClass, Variant: bi.Info.Variant,
			RestoreBehavior: bi.Info.RestoreBehavior,
		}
		for _, name := range manifestComponentNames {
			if name == "OS" && strings.Contains(bi.Info.Variant, "Recovery") {
				continue
			}
			if component, ok := bi.Manifest[name]; ok {
				if path, ok := manifestPath(component); ok {
					identity.Components = append(identity.Components, factsManifestComponent{Name: name, Path: path})
				}
			}
		}
		selection.Identities = append(selection.Identities, identity)
		selection.Devices = append(selection.Devices, device)
		selection.Boards = append(selection.Boards, bi.Info.DeviceClass)
	}
	selection.Devices = sortedNonemptyUnique(selection.Devices)
	selection.Boards = sortedNonemptyUnique(selection.Boards)
	slices.SortFunc(selection.Identities, func(a, b factsManifestIdentity) int {
		return strings.Compare(identitySortKey(a), identitySortKey(b))
	})
	return selection
}

func identitySortKey(identity factsManifestIdentity) string {
	data, _ := json.Marshal(identity)
	return string(data)
}

func sortedNonemptyUnique(values []string) []string {
	values = slices.DeleteFunc(values, func(value string) bool { return value == "" })
	slices.Sort(values)
	return slices.Compact(values)
}

func requestedFactsScopes(cfg *JSONLConfig) []factsRequestedScope {
	var scopes []factsRequestedScope
	if cfg.Kernel || cfg.FileSystem {
		var volumes []string
		if cfg.Kernel {
			volumes = append(volumes, "kernelcache")
		}
		if cfg.FileSystem {
			volumes = append(volumes, "filesystem", "SystemOS", "AppOS", "ExclaveOS")
		}
		scopes = append(scopes, factsRequestedScope{Family: "kernel", Volumes: volumes})
	}
	if cfg.Kernel {
		scopes = append(scopes,
			factsRequestedScope{Family: "kext", Volumes: []string{"kernelcache"}},
		)
	}
	if cfg.DSC {
		scopes = append(scopes, factsRequestedScope{Family: "dsc", Volumes: []string{"SystemOS"}})
	}
	if cfg.FileSystem {
		scopes = append(scopes, factsRequestedScope{
			Family: "filesystem_macho", Volumes: []string{"filesystem", "SystemOS", "AppOS", "ExclaveOS"},
		})
	}
	return scopes
}

func factsCollectionID(version uint32, source factsSourceIdentity, selection factsManifestSelection, requested []factsRequestedScope) (string, error) {
	data, err := json.Marshal(struct {
		Version   uint32                 `json:"version"`
		Source    factsSourceIdentity    `json:"source"`
		Selection factsManifestSelection `json:"selection"`
		Requested []factsRequestedScope  `json:"requested"`
	}{version, source, selection, requested})
	if err != nil {
		return "", fmt.Errorf("failed to bind facts collection: %w", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func componentPaths(selection factsManifestSelection, name string) []string {
	var paths []string
	for _, identity := range selection.Identities {
		for _, component := range identity.Components {
			if component.Name == name {
				paths = append(paths, component.Path)
			}
		}
	}
	return sortedNonemptyUnique(paths)
}

func initialFactsCoverage(cfg *JSONLConfig, selection factsManifestSelection) []factsCoverage {
	rows := []factsCoverage{
		{Family: "kernel", Volume: "kernelcache", ComponentPaths: componentPaths(selection, "KernelCache")},
		{Family: "kernel", Volume: "filesystem", ComponentPaths: componentPaths(selection, "OS")},
		{Family: "kernel", Volume: "SystemOS", ComponentPaths: componentPaths(selection, "Cryptex1,SystemOS")},
		{Family: "kernel", Volume: "AppOS", ComponentPaths: componentPaths(selection, "Cryptex1,AppOS")},
		{Family: "kernel", Volume: "ExclaveOS", ComponentPaths: componentPaths(selection, "Ap,ExclaveOS")},
		{Family: "kext", Volume: "kernelcache", ComponentPaths: componentPaths(selection, "KernelCache")},
		{Family: "dsc", Volume: "SystemOS", RecordVolume: "dyld_shared_cache", ComponentPaths: componentPaths(selection, "Cryptex1,SystemOS")},
		{Family: "filesystem_macho", Volume: "filesystem", ComponentPaths: componentPaths(selection, "OS")},
		{Family: "filesystem_macho", Volume: "SystemOS", ComponentPaths: componentPaths(selection, "Cryptex1,SystemOS")},
		{Family: "filesystem_macho", Volume: "AppOS", ComponentPaths: componentPaths(selection, "Cryptex1,AppOS")},
		{Family: "filesystem_macho", Volume: "ExclaveOS", ComponentPaths: componentPaths(selection, "Ap,ExclaveOS")},
		{Family: "standalone_entitlements", Volume: "all", Status: "unavailable", Reason: "per-image entitlement facts do not prove a complete standalone inventory"},
		{Family: "symbol_table", Volume: "all", Status: "unavailable", Reason: "unsupported"},
		{Family: "cstring_comparison", Volume: "all", Status: "unavailable", Reason: "unsupported"},
		{Family: "function_start_comparison", Volume: "all", Status: "unavailable", Reason: "unsupported"},
	}
	for idx := range rows[:11] {
		selected := rows[idx].Family == "kernel" && rows[idx].Volume == "kernelcache" && cfg.Kernel ||
			rows[idx].Family == "kernel" && rows[idx].Volume != "kernelcache" && cfg.FileSystem ||
			rows[idx].Family == "kext" && cfg.Kernel || rows[idx].Family == "dsc" && cfg.DSC ||
			rows[idx].Family == "filesystem_macho" && cfg.FileSystem
		if !selected {
			rows[idx].Status, rows[idx].Reason = "not-selected", "not requested by CLI selection"
			continue
		}
		rows[idx].Status, rows[idx].Reason = "unavailable", "selected collection did not finish"
		if rows[idx].Volume != "kernelcache" && rows[idx].Volume != "SystemOS" && len(rows[idx].ComponentPaths) == 0 {
			rows[idx].Status, rows[idx].Reason = "absent", "selected BuildManifest has no component for this volume"
		}
	}
	// Older IPSWs use the filesystem image as SystemOS. Preserve the alias as a
	// selected walk, not as an absent volume.
	for _, offset := range []int{1, 7} {
		if cfg.FileSystem && len(rows[offset+1].ComponentPaths) == 0 && len(rows[offset].ComponentPaths) > 0 {
			rows[offset+1].ComponentPaths = slices.Clone(rows[offset].ComponentPaths)
			rows[offset+1].AliasOf = "filesystem"
		}
	}
	if cfg.DSC && len(rows[6].ComponentPaths) == 0 && len(rows[7].ComponentPaths) > 0 {
		rows[6].ComponentPaths = slices.Clone(rows[7].ComponentPaths)
		rows[6].AliasOf = "filesystem"
	}
	for idx := range rows {
		if (rows[idx].Family != "kernel" && rows[idx].Family != "filesystem_macho") || len(rows[idx].ComponentPaths) == 0 {
			continue
		}
		for prior := range idx {
			if rows[prior].Family == rows[idx].Family && slices.Equal(rows[idx].ComponentPaths, rows[prior].ComponentPaths) {
				rows[idx].AliasOf = rows[prior].Volume
				break
			}
		}
	}
	return rows
}

func (c *factsCollection) markSuccessful(family, volume string) {
	for idx := range c.coverage {
		if c.coverage[idx].Family == family && c.coverage[idx].Volume == volume {
			c.coverage[idx].Status, c.coverage[idx].Reason = "successful", ""
			return
		}
	}
}

func (c *factsCollection) completion(emitter *jsonlEmitter) (comparisonFactsCompleteLine, error) {
	coverage := slices.Clone(c.coverage)
	var covered uint64
	for idx := range coverage {
		recordVolume := coverage[idx].Volume
		if coverage[idx].RecordVolume != "" {
			recordVolume = coverage[idx].RecordVolume
		}
		coverage[idx].Records = emitter.factsCounts[coverageKey{coverage[idx].Family, recordVolume}]
		if c.start.CollectionSchemaVersion == factsCollectionSchemaVersionV3 && coverage[idx].Volume == "kernelcache" && coverage[idx].Status == "successful" {
			var total uint64
			counts := emitter.componentCounts[coverageKey{coverage[idx].Family, recordVolume}]
			for _, component := range coverage[idx].ComponentPaths {
				count := counts[component]
				if coverage[idx].Family == "kernel" && count != 1 {
					return comparisonFactsCompleteLine{}, fmt.Errorf("kernel component %q requires exactly one container", component)
				}
				coverage[idx].ComponentRecords = append(coverage[idx].ComponentRecords, factsComponentRecords{Path: component, Records: count})
				total += count
			}
			if len(coverage[idx].ComponentPaths) == 0 || total != coverage[idx].Records {
				return comparisonFactsCompleteLine{}, fmt.Errorf("kernel component coverage does not reconcile")
			}
		}
		covered += coverage[idx].Records
		if coverage[idx].Status == "unavailable" && coverage[idx].Reason == "selected collection did not finish" {
			return comparisonFactsCompleteLine{}, fmt.Errorf("selected facts coverage did not finish: %s/%s", coverage[idx].Family, coverage[idx].Volume)
		}
	}
	if covered != emitter.factsCount {
		return comparisonFactsCompleteLine{}, fmt.Errorf("facts coverage records %d do not reconcile with total %d", covered, emitter.factsCount)
	}
	return comparisonFactsCompleteLine{
		Type: "comparison_facts_complete", CollectionSchemaVersion: c.start.CollectionSchemaVersion,
		CollectionID: c.start.CollectionID, Status: "complete", RequiresSuccessfulProcessExit: true,
		Records:       emitter.factsCount,
		RecordsSHA256: hex.EncodeToString(emitter.factsHash.Sum(nil)), Coverage: coverage,
	}, nil
}
