package diff

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/internal/search"
)

// featuresJob diffs /System/Library/FeatureFlags plists across all four IPSW
// OS volumes. Scan state is partitioned by volume label so Finalize can emit
// a per-volume map matching the d.Features report shape.
type featuresJob struct {
	d *Diff

	volumes      []string
	prevByVolume map[string]map[string]string
	nextByVolume map[string]map[string]string

	// hydrated holds the per-volume feature-flag PlistDiff map loaded from a
	// cache hit (key=volume label, value=*PlistDiff). Non-nil only on the
	// hydrate path; Finalize publishes it directly to j.d.Features and skips
	// the volume fold. A zero-row hit hydrates to a non-nil empty map so
	// Finalize still takes the hydrate branch and publishes the empty result.
	hydrated map[string]*PlistDiff
}

var _ CacheableTask = (*featuresJob)(nil)

func newFeaturesJob(d *Diff) *featuresJob {
	return &featuresJob{
		d:            d,
		prevByVolume: make(map[string]map[string]string),
		nextByVolume: make(map[string]map[string]string),
	}
}

func (j *featuresJob) Name() string { return "features" }

func (j *featuresJob) Needs(typ string) bool {
	switch typ {
	case "fs", "sys", "app", "exc":
		return true
	}
	return false
}

func (j *featuresJob) ProcessVolume(typ, oldRoot, newRoot string) error {
	label := volumeLabel(typ)
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
		if err := search.ForEachPlistInMount(oldRoot, "/System/Library/FeatureFlags", func(path, content string) error {
			prev[path] = content
			return nil
		}); err != nil {
			return err
		}
	}
	if newRoot != "" {
		if err := search.ForEachPlistInMount(newRoot, "/System/Library/FeatureFlags", func(path, content string) error {
			next[path] = content
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// Finalize folds the per-volume feature-flag buckets into the PlistDiff map on
// the Diff. On the cache-hit path (j.hydrated non-nil) the orchestrator
// excluded the task from the volume walk, so there is no per-volume scan state
// to fold: publish the hydrated result directly.
func (j *featuresJob) Finalize() error {
	if j.hydrated != nil {
		j.d.Features = j.hydrated
		return nil
	}

	out, err := buildPlistDiffByVolume(j.volumes, j.prevByVolume, j.nextByVolume)
	if err != nil {
		return err
	}
	j.d.Features = out
	j.prevByVolume = nil
	j.nextByVolume = nil
	return nil
}

// featuresCacheVersion is the cache payload / output-semantics version for
// featuresJob. Bump it whenever the persisted row layout (per-volume
// *PlistDiff), the scanned path (/System/Library/FeatureFlags) and plist
// extraction, or the rendered Feature Flags section semantics change in a way
// that invalidates rows written by a prior ipsw build.
const featuresCacheVersion = 1

// Version reports the cache payload / output-semantics version. See
// featuresCacheVersion.
func (j *featuresJob) Version() int { return featuresCacheVersion }

// OptionsHash digests every output-affecting option for featuresJob. The job
// has no output-affecting flags: it always scans the fixed
// /System/Library/FeatureFlags path on every OS volume, captures plist content
// verbatim, and renders it through the fixed buildPlistDiffByVolume /
// renderPlistVolume path. There are no allow/block lists, no verbosity, and no
// diff-tool selection. The only thing that can change the rendered bytes is the
// scan/render logic itself, which is tracked by the stable scan-semantics tag
// and featuresCacheVersion.
func (j *featuresJob) OptionsHash() string {
	return constOptionsHash("features-options-v-root-symlinks", featuresCacheVersion)
}

// InputHash digests the task-scope inputs: the old and new BuildManifest DMG
// digests for every volume featuresJob reads (fs/sys/app/exc). It delegates to
// volumeDMGInputHash, the shared per-volume fingerprint that machosJob and
// entsJob also use, because every OS-volume job walks the identical four
// volumes.
func (j *featuresJob) InputHash() string {
	return volumeDMGInputHash(j.d.Old.Info, j.d.New.Info)
}

// featuresCacheRowKey is the row key for a volume's cached feature-flag
// PlistDiff. The key is the volume label so a hydrate can rebuild the
// per-volume map directly.
func featuresCacheRowKey(label string) string { return label }

// Hydrate rebuilds the per-volume feature-flag PlistDiff result from a cache
// hit. Each row is keyed by volume label and holds a gob-encoded *PlistDiff.
// The decoded map is stashed in j.hydrated for Finalize to publish; the volume
// walk is skipped entirely by the orchestrator. A zero-row hit yields a non-nil
// empty map so Finalize still takes the hydrate branch.
func (j *featuresJob) Hydrate(scope storage.Scope, store storage.Store) error {
	out := make(map[string]*PlistDiff)
	err := store.Iter(scope, func(key string, decode func(v any) error) error {
		var diff PlistDiff
		if err := decode(&diff); err != nil {
			return fmt.Errorf("features: hydrate %s: %w", key, err)
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
// from j.d.Features (the published result) rather than the per-side buckets,
// which Finalize has already cleared. Finalize already dropped empty volumes via
// buildPlistDiffByVolume, so an all-empty result writes zero rows.
func (j *featuresJob) persistTo(scope storage.Scope, store storage.Store) error {
	for label, diff := range j.d.Features {
		if err := store.Put(scope, featuresCacheRowKey(label), diff); err != nil {
			return fmt.Errorf("features: persist %s: %w", label, err)
		}
	}
	return nil
}

// featuresRenderer owns the per-task Markdown/HTML/JSON emission for the
// `## Feature Flags` section. Render-time state is the per-volume
// PlistDiff map produced by [featuresJob.Finalize].
type featuresRenderer struct {
	volumes map[string]*PlistDiff
}

func newFeaturesRenderer(volumes map[string]*PlistDiff) *featuresRenderer {
	return &featuresRenderer{volumes: volumes}
}

// JSONKey returns the stable JSON key that feature-flag payloads embed
// under in the top-level report DTO.
func (r *featuresRenderer) JSONKey() string { return "features" }

// Empty reports whether the section has no rendered content.
func (r *featuresRenderer) Empty() bool { return !hasPlistVolumeContent(r.volumes) }

// Markdown emits the `## Feature Flags` section, including the per-volume
// `### {volume}` sub-headings. The byte sequence must remain identical to
// the prior inlined body in md.go.
func (r *featuresRenderer) Markdown(out *strings.Builder, outputDir string) error {
	if r.Empty() {
		return nil
	}
	out.WriteString("## Feature Flags\n\n")
	for _, vol := range sortedVolumeKeys(r.volumes) {
		diff := r.volumes[vol]
		if !plistDiffHasContent(diff) {
			continue
		}
		fmt.Fprintf(out, "### %s\n\n", vol)
		if err := renderPlistVolume(out, diff, outputDir, "####", vol, featureFlagsRenderer); err != nil {
			return err
		}
	}
	return nil
}

// featuresHTMLTemplate renders the per-volume Feature Flags body. It must
// produce bytes identical to the slice of diffHTMLPageTemplate it replaces.
const featuresHTMLTemplate = `
{{- range . }}
          <h3 id="features-{{ .Name | slug }}">{{ .Name }}</h3>
          {{- template "plistDiffSection" dict "Prefix" (printf "features-%s" (.Name | slug)) "Diff" .Diff }}
{{- end }}`

// HTML returns the per-task HTML fragment for the `Feature Flags` section.
// The fragment Body excludes the section's <h2> heading.
func (r *featuresRenderer) HTML() (HTMLFragment, error) {
	volumes := convertPlistVolumeDiff(r.volumes, filepath.Base)
	if len(volumes) == 0 {
		return HTMLFragment{Heading: "Feature Flags"}, nil
	}
	body, err := executeHTMLTaskTemplate("features-html", featuresHTMLTemplate, volumes)
	if err != nil {
		return HTMLFragment{}, err
	}
	return HTMLFragment{Heading: "Feature Flags", Body: body}, nil
}

// JSON returns the per-task report payload: the per-volume feature-flag
// PlistDiff map embedded under [featuresRenderer.JSONKey] in the top-level
// report DTO. Returns the underlying map as-is so buildReport's omitempty
// handling matches the legacy `Diff.Features` field encoding.
func (r *featuresRenderer) JSON() any {
	return r.volumes
}
