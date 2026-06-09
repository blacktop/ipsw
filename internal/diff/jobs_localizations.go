package diff

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/internal/search"
)

// locsJob diffs localized resources (.strings, .stringsdict, .loctable)
// across all four IPSW OS volumes. Scan state is partitioned by volume
// label and Finalize emits the per-volume d.Localizations map.
type locsJob struct {
	d *Diff

	volumes      []string
	prevByVolume map[string]map[string]string
	nextByVolume map[string]map[string]string

	// hydrated holds the per-volume localization PlistDiff map loaded from a
	// cache hit (key=volume label, value=*PlistDiff). Non-nil only on the
	// hydrate path; Finalize publishes it directly to j.d.Localizations and
	// skips the volume fold. A zero-row hit hydrates to a non-nil empty map so
	// Finalize still takes the hydrate branch and publishes the empty result.
	hydrated map[string]*PlistDiff
}

var _ CacheableTask = (*locsJob)(nil)

func newLocalizationsJob(d *Diff) *locsJob {
	return &locsJob{
		d:            d,
		prevByVolume: make(map[string]map[string]string),
		nextByVolume: make(map[string]map[string]string),
	}
}

func (j *locsJob) Name() string { return "localizations" }

func (j *locsJob) Needs(typ string) bool {
	switch typ {
	case "fs", "sys", "app", "exc":
		return true
	}
	return false
}

func (j *locsJob) ProcessVolume(typ, oldRoot, newRoot string) error {
	label := volumeListDMGLabel(typ)
	trackVolumeOnce(&j.volumes, label)
	if j.prevByVolume[label] == nil {
		j.prevByVolume[label] = make(map[string]string)
	}
	if j.nextByVolume[label] == nil {
		j.nextByVolume[label] = make(map[string]string)
	}
	prev := j.prevByVolume[label]
	next := j.nextByVolume[label]
	if oldRoot != "" {
		if err := search.ForEachFileInMount(oldRoot, label, "", func(_, rel string) error {
			return collectLocalizedResourceFile(prev, label, oldRoot, filepath.Join(oldRoot, rel))
		}); err != nil {
			return fmt.Errorf("failed to scan %s localizations: %w", label, err)
		}
	}
	if newRoot != "" {
		if err := search.ForEachFileInMount(newRoot, label, "", func(_, rel string) error {
			return collectLocalizedResourceFile(next, label, newRoot, filepath.Join(newRoot, rel))
		}); err != nil {
			return fmt.Errorf("failed to scan %s localizations: %w", label, err)
		}
	}
	return nil
}

// Finalize folds the per-volume localization buckets into the PlistDiff map on
// the Diff. On the cache-hit path (j.hydrated non-nil) the orchestrator
// excluded the task from the volume walk, so there is no per-volume scan state
// to fold: publish the hydrated result directly.
func (j *locsJob) Finalize() error {
	if j.hydrated != nil {
		j.d.Localizations = j.hydrated
		return nil
	}

	out, err := assembleLocalizationDiffByVolume(j.volumes, j.prevByVolume, j.nextByVolume)
	if err != nil {
		return err
	}
	j.d.Localizations = out
	j.prevByVolume = nil
	j.nextByVolume = nil
	return nil
}

// locsCacheVersion is the cache payload / output-semantics version for locsJob.
// Bump it whenever the persisted row layout (per-volume *PlistDiff), the
// localized-resource scan (.strings / .stringsdict / .loctable selection and
// extraction), or the rendered Localizations section semantics change in a way
// that invalidates rows written by a prior ipsw build.
const locsCacheVersion = 1

// Version reports the cache payload / output-semantics version. See
// locsCacheVersion.
func (j *locsJob) Version() int { return locsCacheVersion }

// OptionsHash digests every output-affecting option for locsJob. The job has no
// output-affecting flags: it always scans every OS volume for the fixed
// localized-resource set (.strings / .stringsdict / .loctable), captures their
// content, and renders it through the fixed assembleLocalizationDiffByVolume /
// renderPlistVolume path. There are no allow/block lists, no verbosity, and no
// diff-tool selection. The only thing that can change the rendered bytes is the
// scan/render logic itself, which is tracked by the stable scan-semantics tag
// and locsCacheVersion.
func (j *locsJob) OptionsHash() string {
	return constOptionsHash("localizations-options-v-root-symlinks", locsCacheVersion)
}

// InputHash digests the task-scope inputs: the old and new BuildManifest DMG
// digests for every volume locsJob reads (fs/sys/app/exc). It delegates to
// volumeDMGInputHash, the shared per-volume fingerprint that machosJob and
// entsJob also use, because every OS-volume job walks the identical four
// volumes.
func (j *locsJob) InputHash() string {
	return volumeDMGInputHash(j.d.Old.Info, j.d.New.Info)
}

// locsCacheRowKey is the row key for a volume's cached localization PlistDiff.
// The key is the volume label so a hydrate can rebuild the per-volume map
// directly.
func locsCacheRowKey(label string) string { return label }

// Hydrate rebuilds the per-volume localization PlistDiff result from a cache
// hit. Each row is keyed by volume label and holds a gob-encoded *PlistDiff.
// The decoded map is stashed in j.hydrated for Finalize to publish; the volume
// walk is skipped entirely by the orchestrator. A zero-row hit yields a non-nil
// empty map so Finalize still takes the hydrate branch.
func (j *locsJob) Hydrate(scope storage.Scope, store storage.Store) error {
	out := make(map[string]*PlistDiff)
	err := store.Iter(scope, func(key string, decode func(v any) error) error {
		var diff PlistDiff
		if err := decode(&diff); err != nil {
			return fmt.Errorf("localizations: hydrate %s: %w", key, err)
		}
		out[key] = &diff
		return nil
	})
	if err != nil {
		return err
	}
	j.hydrated = out
	return nil
}

// persistTo writes one row per content-bearing volume from the freshly-computed
// result. It runs only after a successful fresh walk + Finalize, so it reads
// from j.d.Localizations (the published result) rather than the per-side
// buckets, which Finalize has already cleared. Finalize already dropped empty
// volumes via assembleLocalizationDiffByVolume, so an all-empty result writes
// zero rows.
func (j *locsJob) persistTo(scope storage.Scope, store storage.Store) error {
	for label, diff := range j.d.Localizations {
		if err := store.Put(scope, locsCacheRowKey(label), diff); err != nil {
			return fmt.Errorf("localizations: persist %s: %w", label, err)
		}
	}
	return nil
}

// locsRenderer owns the per-task Markdown/HTML/JSON emission for the
// `## Localizations` section. Render-time state is the per-volume
// PlistDiff map produced by [locsJob.Finalize].
type locsRenderer struct {
	volumes map[string]*PlistDiff
}

func newLocsRenderer(volumes map[string]*PlistDiff) *locsRenderer {
	return &locsRenderer{volumes: volumes}
}

// JSONKey returns the stable JSON key that localizations payloads embed
// under in the top-level report DTO.
func (r *locsRenderer) JSONKey() string { return "localizations" }

// Empty reports whether the section has no rendered content.
func (r *locsRenderer) Empty() bool { return !hasPlistVolumeContent(r.volumes) }

// Markdown emits the `## Localizations` section, including the per-volume
// `### {volume}` sub-headings. The byte sequence must remain identical to
// the prior inlined body in md.go.
func (r *locsRenderer) Markdown(out *strings.Builder, outputDir string) error {
	if r.Empty() {
		return nil
	}
	out.WriteString("## Localizations\n\n")
	for _, vol := range sortedVolumeKeys(r.volumes) {
		diff := r.volumes[vol]
		if !plistDiffHasContent(diff) {
			continue
		}
		fmt.Fprintf(out, "### %s\n\n", vol)
		if err := renderPlistVolume(out, diff, outputDir, "####", vol, localizationsRenderer); err != nil {
			return err
		}
	}
	return nil
}

// localizationsHTMLTemplate renders the per-volume Localizations body. It
// must produce bytes identical to the slice of diffHTMLPageTemplate it
// replaces.
const localizationsHTMLTemplate = `
{{- range . }}
          <h3 id="localizations-{{ .Name | slug }}">{{ .Name }}</h3>
          {{- template "plistDiffSection" dict "Prefix" (printf "localizations-%s" (.Name | slug)) "Diff" .Diff }}
{{- end }}`

// HTML returns the per-task HTML fragment for the `Localizations` section.
// The fragment Body excludes the section's <h2> heading.
func (r *locsRenderer) HTML() (HTMLFragment, error) {
	volumes := convertPlistVolumeDiff(r.volumes, localizationDisplayName)
	if len(volumes) == 0 {
		return HTMLFragment{Heading: "Localizations"}, nil
	}
	body, err := executeHTMLTaskTemplate("localizations-html", localizationsHTMLTemplate, volumes)
	if err != nil {
		return HTMLFragment{}, err
	}
	return HTMLFragment{Heading: "Localizations", Body: body}, nil
}

// JSON returns the per-task report payload: the per-volume localization
// PlistDiff map embedded under [locsRenderer.JSONKey] in the top-level
// report DTO. Returns the underlying map as-is so buildReport's omitempty
// handling matches the legacy `Diff.Localizations` field encoding.
func (r *locsRenderer) JSON() any {
	return r.volumes
}
