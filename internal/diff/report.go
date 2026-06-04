package diff

import (
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
)

// buildReport assembles the stable per-section report DTO that the
// JSON output path marshals. Mount-based jobs (machos, ents, features,
// localizations, launchd, files) and the migrated top-level tasks
// (kexts, kdks, firmwares, iboot, sandbox) contribute via their
// JSON() payloads keyed by JSONKey() (duck-typed through
// [reportContributor]); the still-inlined DSC/Dylibs section comes
// straight off the [Diff] fields. The map preserves the legacy
// `omitempty` shape: zero values for each contributing field are
// dropped so the JSON output remains byte-compatible with the pre-DTO
// `json.MarshalIndent(d, …)` path modulo whitespace normalization (the
// parity tests cover both raw bytes and map round-trip equivalence).
func buildReport(d *Diff) (map[string]any, error) {
	report := make(map[string]any, 13)

	// Title — top-level scalar, legacy `Diff.Title` had `omitempty`.
	if d.Title != "" {
		report["title"] = d.Title
	}

	// DSC/Dylibs stays mount-bound; preserved directly off the [Diff]
	// field until the DSC task migration lands.
	if d.Dylibs != nil {
		report["dylibs"] = d.Dylibs
	}

	// Migrated top-level tasks contribute through their renderers.
	addMachoDiffIfNotNil(report, newKextsTask(d))
	addStringIfNotEmpty(report, newKDKsTask(d))
	addMachoDiffIfNotNil(report, newFirmwaresTask(d))
	addIBootIfNotNil(report, newIBootTask(d))
	addStringIfNotEmpty(report, newSandboxTask(d))

	// Mount-based jobs route through their renderers. JSON() returns the
	// underlying typed field, so the per-key zero-value guards below
	// reproduce the original `omitempty` behavior.
	addMapIfNotEmpty(report, newMachosRenderer(d.Machos))
	addMapIfNotEmpty(report, newEntsRenderer(d.Ents))
	addMapIfNotEmpty(report, newFeaturesRenderer(d.Features))
	addMapIfNotEmpty(report, newLocsRenderer(d.Localizations))
	addPtrIfNotNil(report, newFilesRenderer(d.Files))
	addStringIfNotEmpty(report, newLaunchdRenderer(d.Launchd))

	return report, nil
}

// reportContributor is the minimal renderer surface buildReport relies on.
// Each helper below narrows the JSON() return type so the `omitempty`
// equivalent guard is exact, not reflection-based.
type reportContributor interface {
	JSONKey() string
	JSON() any
}

// addMapIfNotEmpty embeds the renderer's payload when JSON() returns a
// non-empty map. Mirrors `omitempty` on a `map[K]V` field.
func addMapIfNotEmpty(report map[string]any, r reportContributor) {
	switch v := r.JSON().(type) {
	case map[string]string:
		if len(v) > 0 {
			report[r.JSONKey()] = v
		}
	case map[string]*PlistDiff:
		if len(v) > 0 {
			report[r.JSONKey()] = v
		}
	case map[string]*mcmd.MachoDiff:
		if len(v) > 0 {
			report[r.JSONKey()] = v
		}
	}
}

// addPtrIfNotNil embeds the renderer's payload when JSON() returns a
// non-nil pointer. Mirrors `omitempty` on a `*T` field.
func addPtrIfNotNil(report map[string]any, r reportContributor) {
	if v, ok := r.JSON().(*FileDiff); ok && v != nil {
		report[r.JSONKey()] = v
	}
}

// addStringIfNotEmpty embeds the renderer's payload when JSON() returns a
// non-empty string. Mirrors `omitempty` on a `string` field.
func addStringIfNotEmpty(report map[string]any, r reportContributor) {
	if s, ok := r.JSON().(string); ok && s != "" {
		report[r.JSONKey()] = s
	}
}

// addMachoDiffIfNotNil embeds the renderer's payload when JSON() returns
// a non-nil [*mcmd.MachoDiff]. Mirrors `omitempty` on a `*mcmd.MachoDiff`
// field.
func addMachoDiffIfNotNil(report map[string]any, r reportContributor) {
	if v, ok := r.JSON().(*mcmd.MachoDiff); ok && v != nil {
		report[r.JSONKey()] = v
	}
}

// addIBootIfNotNil embeds the renderer's payload when JSON() returns a
// non-nil [*IBootDiff]. Mirrors `omitempty` on a `*IBootDiff` field.
func addIBootIfNotNil(report map[string]any, r reportContributor) {
	if v, ok := r.JSON().(*IBootDiff); ok && v != nil {
		report[r.JSONKey()] = v
	}
}
