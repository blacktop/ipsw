package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	cstypes "github.com/blacktop/go-macho/pkg/codesign/types"
	ents "github.com/blacktop/ipsw/internal/codesign/entitlements"
	"github.com/blacktop/ipsw/internal/diff/storage"
)

// entsJob diffs entitlement databases per IPSW OS volume. It participates
// in the shared per-volume Mach-O walk via [MachoWalkTask] so the
// code-signature blob extraction piggybacks on the same walk that feeds
// machosJob — one filesystem traversal, one Mach-O open per binary.
//
// Per-volume entitlement maps are partitioned by side and folded by
// [renderEntitlementsDiff] in Finalize, preserving the existing d.Ents
// report shape.
type entsJob struct {
	d *Diff

	volumes      []string
	prevByVolume map[string]map[string]string
	nextByVolume map[string]map[string]string

	// hydrated holds the per-volume rendered entitlement-diff strings loaded
	// from a cache hit (key=volume label, value=rendered diff). Non-nil only on
	// the hydrate path; Finalize publishes it directly to j.d.Ents and skips the
	// volume fold. The orchestrator excludes a hydrated task from the volume
	// walk, so the per-side buckets stay empty.
	hydrated map[string]string
}

var _ CacheableTask = (*entsJob)(nil)

func newEntitlementsJob(d *Diff) *entsJob {
	return &entsJob{
		d:            d,
		prevByVolume: make(map[string]map[string]string),
		nextByVolume: make(map[string]map[string]string),
	}
}

func (j *entsJob) Name() string { return "entitlements" }

func (j *entsJob) Needs(typ string) bool {
	switch typ {
	case "fs", "sys", "app", "exc":
		return true
	}
	return false
}

// BeginVolume initializes the per-volume entitlement buckets so the
// per-side handler closures can write into stable map references.
func (j *entsJob) BeginVolume(typ string) error {
	label := volumeLabel(typ)
	trackVolumeOnce(&j.volumes, label)
	if j.prevByVolume[label] == nil {
		j.prevByVolume[label] = make(map[string]string)
	}
	if j.nextByVolume[label] == nil {
		j.nextByVolume[label] = make(map[string]string)
	}
	return nil
}

// MachoHandler returns the per-binary closure for the requested side. The
// closure inlines the per-binary code-signature blob extraction from
// ent.GetDatabase: plain entitlements with DER fallback, plus launch
// constraints (self/parent/responsible) when present.
func (j *entsJob) MachoHandler(typ string, side Side) MachoScanHandler {
	label := volumeLabel(typ)
	var bucket map[string]string
	switch side {
	case SideOld:
		bucket = j.prevByVolume[label]
	case SideNew:
		bucket = j.nextByVolume[label]
	default:
		return nil
	}
	return func(path string, m *macho.File) error {
		bucket[path] = extractMachoEntitlements(path, m)
		return nil
	}
}

// EndVolume is a no-op for ents: the per-volume diff is rendered in
// Finalize once both sides have populated their buckets.
func (j *entsJob) EndVolume(typ string) error { return nil }

// AbortVolume discards any partial entitlement buckets for typ after a
// shared-walk failure. Entitlement extraction normally cannot fail per binary,
// but keeping this hook makes the task safe if future handlers add errors.
func (j *entsJob) AbortVolume(typ string) {
	label := volumeLabel(typ)
	delete(j.prevByVolume, label)
	delete(j.nextByVolume, label)
	removeVolume(&j.volumes, label)
}

// Finalize folds the per-volume entitlement buckets into the rendered diff
// map on the Diff. On the cache-hit path (j.hydrated non-nil) the orchestrator
// excluded the task from the volume walk, so there is no per-volume scan state
// to fold: publish the hydrated result directly.
func (j *entsJob) Finalize() error {
	if j.hydrated != nil {
		j.d.Ents = j.hydrated
		return nil
	}

	out := make(map[string]string, len(j.volumes))
	for _, label := range j.volumes {
		rendered, err := renderEntitlementsDiff(j.prevByVolume[label], j.nextByVolume[label])
		if err != nil {
			return err
		}
		if entitlementsDiffHasContent(rendered) {
			out[label] = rendered
		}
	}
	j.d.Ents = out
	j.prevByVolume = nil
	j.nextByVolume = nil
	return nil
}

// extractMachoEntitlements returns the entitlements payload for one
// Mach-O binary, mirroring the per-file extraction in ent.GetDatabase:
// plain XML entitlements with DER fallback, optionally followed by
// launch-constraint sections (self/parent/responsible) when present.
// path is only used for diagnostic logging on the DER fallback.
func extractMachoEntitlements(path string, m *macho.File) string {
	cs := m.CodeSignature()
	if cs == nil {
		return ""
	}
	var out strings.Builder
	switch {
	case len(cs.Entitlements) > 0:
		out.WriteString(cs.Entitlements)
	case len(cs.EntitlementsDER) > 0:
		if decoded, err := ents.DerDecode(cs.EntitlementsDER); err == nil {
			out.WriteString(decoded)
			log.Warnf("using DER entitlements for %s", path)
		}
	}
	appendLaunchConstraint(&out, "Self", cs.LaunchConstraintsSelf)
	appendLaunchConstraint(&out, "Parent", cs.LaunchConstraintsParent)
	appendLaunchConstraint(&out, "Responsible", cs.LaunchConstraintsResponsible)
	return out.String()
}

// entsCacheVersion is the cache payload / output-semantics version for
// entsJob. Bump it whenever the persisted row layout (per-volume rendered
// entitlement-diff string), the entitlement extraction (XML / DER fallback /
// launch constraints), or the rendered Entitlements section semantics change in
// a way that invalidates rows written by a prior ipsw build.
const entsCacheVersion = 1

// Version reports the cache payload / output-semantics version. See
// entsCacheVersion.
func (j *entsJob) Version() int { return entsCacheVersion }

// OptionsHash digests every output-affecting option for entsJob. The job has
// no output-affecting flags: it always extracts plain XML entitlements with a
// DER fallback plus the self/parent/responsible launch constraints, and renders
// them with the fixed renderEntitlementsDiff path. There are no allow/block
// lists, no verbosity, and no diff-tool selection. The tag also names the mount
// symlink policy because that changes the scanned Mach-O set without changing
// the IPSW volume digests.
func (j *entsJob) OptionsHash() string {
	return constOptionsHash("entitlements-options-v-mount-root-symlinks", entsCacheVersion)
}

// InputHash digests the task-scope inputs: the old and new BuildManifest DMG
// digests for every volume entsJob reads (fs/sys/app/exc). It delegates to
// volumeDMGInputHash, the shared per-volume fingerprint that machosJob also
// uses, because both jobs walk the identical four volumes.
func (j *entsJob) InputHash() string {
	return volumeDMGInputHash(j.d.Old.Info, j.d.New.Info)
}

// entsCacheRowKey is the row key for a volume's cached entitlement-diff string.
// The key is the volume label so a hydrate can rebuild the per-volume map
// directly.
func entsCacheRowKey(label string) string { return label }

// Hydrate rebuilds the per-volume rendered entitlement-diff result from a cache
// hit. Each row is keyed by volume label and holds a gob-encoded string. The
// decoded map is stashed in j.hydrated for Finalize to publish; the volume walk
// is skipped entirely by the orchestrator.
func (j *entsJob) Hydrate(scope storage.Scope, store storage.Store) error {
	out := make(map[string]string)
	err := store.Iter(scope, func(key string, decode func(v any) error) error {
		var rendered string
		if err := decode(&rendered); err != nil {
			return fmt.Errorf("entitlements: hydrate %s: %w", key, err)
		}
		out[key] = rendered
		return nil
	})
	if err != nil {
		return err
	}
	j.hydrated = out
	return nil
}

// persistTo writes one row per volume label from the freshly-computed result.
// It runs only after a successful fresh walk + Finalize, so it reads from
// j.d.Ents (the published result) rather than the per-side buckets, which
// Finalize has already cleared.
func (j *entsJob) persistTo(scope storage.Scope, store storage.Store) error {
	for label, rendered := range j.d.Ents {
		if err := store.Put(scope, entsCacheRowKey(label), rendered); err != nil {
			return fmt.Errorf("entitlements: persist %s: %w", label, err)
		}
	}
	return nil
}

// entsRenderer owns the per-task Markdown/HTML/JSON emission for the
// `### 🔑 Entitlements` section. Render-time state is the per-volume
// rendered-diff map produced by [entsJob.Finalize].
type entsRenderer struct {
	volumes map[string]string
}

func newEntsRenderer(volumes map[string]string) *entsRenderer {
	return &entsRenderer{volumes: volumes}
}

// JSONKey returns the stable JSON key that entitlements payloads embed
// under in the top-level report DTO.
func (r *entsRenderer) JSONKey() string { return "ents" }

// Empty reports whether the section has no rendered content.
func (r *entsRenderer) Empty() bool { return !hasEntitlementsContent(r.volumes) }

// Markdown emits the `### 🔑 Entitlements` README stub and writes the
// Entitlements.md side-effect file containing the per-volume rendered
// diffs. The byte sequence must remain identical to the prior inlined
// body in md.go.
func (r *entsRenderer) Markdown(out *strings.Builder, outputDir string) error {
	if r.Empty() {
		return nil
	}
	out.WriteString("### 🔑 Entitlements\n\n")
	fname := filepath.Join(outputDir, "Entitlements.md")
	log.Debugf("Creating diff Entitlements Markdown: %s", fname)
	f, err := os.Create(fname)
	if err != nil {
		return fmt.Errorf("failed to create diff Entitlements Markdown: %w", err)
	}
	fmt.Fprintf(f, "## 🔑 Entitlements\n\n")
	for _, vol := range sortedVolumeKeys(r.volumes) {
		rendered := r.volumes[vol]
		if !entitlementsDiffHasContent(rendered) {
			continue
		}
		fmt.Fprintf(f, "### %s\n\n%s\n\n", vol, rendered)
	}
	f.Close()
	fmt.Fprintf(out, "- [%s](%s)\n\n", "Entitlements DIFF", "Entitlements.md")
	return nil
}

// entsHTMLTemplate renders the per-volume Entitlements body. It must
// produce bytes identical to the slice of diffHTMLPageTemplate it replaces.
const entsHTMLTemplate = `
{{- range . }}
          <h3 id="entitlements-{{ .Name | slug }}">{{ .Name }}</h3>
          <details>
            <summary>View Entitlements</summary>
            {{ .Content }}
          </details>
{{- end }}`

// HTML returns the per-task HTML fragment for the `Entitlements` section.
// The fragment Body excludes the section's <h2> heading.
func (r *entsRenderer) HTML() (HTMLFragment, error) {
	volumes := convertEntitlementsDiff(r.volumes)
	if len(volumes) == 0 {
		return HTMLFragment{Heading: "Entitlements"}, nil
	}
	body, err := executeHTMLTaskTemplate("entitlements-html", entsHTMLTemplate, volumes)
	if err != nil {
		return HTMLFragment{}, err
	}
	return HTMLFragment{Heading: "Entitlements", Body: body}, nil
}

// JSON returns the per-task report payload: the per-volume rendered
// entitlements-diff map embedded under [entsRenderer.JSONKey] in the
// top-level report DTO. Returns the underlying map as-is so buildReport's
// omitempty handling matches the legacy `Diff.Ents` field encoding.
func (r *entsRenderer) JSON() any {
	return r.volumes
}

// appendLaunchConstraint renders one optional launch-constraint blob with
// the same formatting used by ent.GetDatabase: an HTML comment header and
// a 2-space-indented JSON object, prefixed with a blank line when the
// builder already contains content.
func appendLaunchConstraint(out *strings.Builder, label string, blob []byte) {
	if len(blob) == 0 {
		return
	}
	lc, err := cstypes.ParseLaunchContraints(blob)
	if err != nil {
		return
	}
	if out.Len() > 0 {
		out.WriteString("\n")
	}
	out.WriteString("<!-- Launch Constraints (")
	out.WriteString(label)
	out.WriteString(") -->\n")
	data, err := json.MarshalIndent(lc, "", "  ")
	if err == nil {
		out.Write(data)
	}
	out.WriteString("\n")
}
