package diff

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/blacktop/ipsw/internal/diff/storage"
)

// launchdJob diffs the launchd configuration embedded in /sbin/launchd.
// It only needs the "fs" volume (FileSystem DMG, where /sbin/launchd lives).
type launchdJob struct {
	d *Diff

	// hydrated holds the rendered launchd-diff string loaded from a cache hit.
	// A non-nil pointer (even to "") marks the hydrate path so Finalize
	// publishes it directly to j.d.Launchd and skips the volume walk; nil means
	// "not hydrated". An empty hit is distinguishable from "not hydrated".
	hydrated *string
}

var _ CacheableTask = (*launchdJob)(nil)

func newLaunchdJob(d *Diff) *launchdJob {
	return &launchdJob{d: d}
}

func (j *launchdJob) Name() string { return "launchd" }

func (j *launchdJob) Needs(typ string) bool { return typ == "fs" }

// ProcessVolume extracts launchd config from both fs roots and writes the
// git-diff result to d.Launchd directly. The result string is small (just
// the formatted diff), so no per-volume accumulation is needed.
func (j *launchdJob) ProcessVolume(typ, oldRoot, newRoot string) error {
	oldConfig, err := launchdConfigFromRoots([]string{oldRoot})
	if err != nil {
		return fmt.Errorf("failed to read Old launchd config: %w", err)
	}
	newConfig, err := launchdConfigFromRoots([]string{newRoot})
	if err != nil {
		return fmt.Errorf("failed to read New launchd config: %w", err)
	}
	return j.d.applyLaunchdGitDiff(oldConfig, newConfig)
}

// Finalize publishes the result. On the cache-hit path (j.hydrated non-nil) the
// orchestrator excluded the task from the volume walk, so ProcessVolume never
// ran: publish the hydrated string directly. On a fresh walk ProcessVolume has
// already set j.d.Launchd, so Finalize is a no-op.
func (j *launchdJob) Finalize() error {
	if j.hydrated != nil {
		j.d.Launchd = *j.hydrated
		return nil
	}
	return nil
}

// launchdCacheVersion is the cache payload / output-semantics version for
// launchdJob. Bump it whenever the persisted row layout (the rendered launchd
// git-diff string), the launchd config extraction, or the rendered launchd
// Config section semantics change in a way that invalidates rows written by a
// prior ipsw build.
const launchdCacheVersion = 1

// Version reports the cache payload / output-semantics version. See
// launchdCacheVersion.
func (j *launchdJob) Version() int { return launchdCacheVersion }

// OptionsHash digests every output-affecting option for launchdJob. The job has
// no output-affecting flags: it always extracts /sbin/launchd's embedded config
// from the fs volume and renders it through the fixed applyLaunchdGitDiff path
// (git diff, no color, fenced as ```diff). There are no allow/block lists, no
// verbosity, and no diff-tool selection. The only thing that can change the
// rendered bytes is the extraction/render logic itself, which is tracked by the
// stable scan-semantics tag and launchdCacheVersion.
func (j *launchdJob) OptionsHash() string {
	return constOptionsHash("launchd-options-v-root-symlinks", launchdCacheVersion)
}

// InputHash digests the task-scope inputs: the old and new BuildManifest DMG
// digests for the ONLY volume launchdJob reads (fs). Unlike the sibling
// OS-volume jobs, launchd reads /sbin/launchd from the FileSystem DMG alone, so
// its cache identity must ignore sys/app/exc digest changes — a SystemOS-only
// rebuild must still serve the cached launchd diff. It folds just "fs" via
// volumeDMGInputHashFor.
func (j *launchdJob) InputHash() string {
	return volumeDMGInputHashFor(j.d.Old.Info, j.d.New.Info, "fs")
}

// launchdCacheRowKey is the single row key for the cached launchd-diff string.
const launchdCacheRowKey = "launchd"

// Hydrate rebuilds the rendered launchd-diff result from a cache hit. The
// single row holds a gob-encoded string. The decoded value is stashed in
// j.hydrated (a non-nil pointer even when "") for Finalize to publish; the
// volume walk is skipped entirely by the orchestrator. A zero-row hit (the
// empty-result case, where persistTo wrote nothing) yields a non-nil pointer to
// "" so Finalize still takes the hydrate branch and publishes the empty result.
func (j *launchdJob) Hydrate(scope storage.Scope, store storage.Store) error {
	body := ""
	err := store.Iter(scope, func(key string, decode func(v any) error) error {
		var rendered string
		if err := decode(&rendered); err != nil {
			return fmt.Errorf("launchd: hydrate %s: %w", key, err)
		}
		body = rendered
		return nil
	})
	if err != nil {
		return err
	}
	j.hydrated = &body
	return nil
}

// persistTo writes the launchd-diff string from the freshly-computed result. It
// runs only after a successful fresh walk + Finalize, so it reads from
// j.d.Launchd (the published result). It mirrors applyLaunchdGitDiff's "only set
// d.Launchd when the diff is non-empty" behavior: an empty result writes zero
// rows, matching the empty-result contract (a later zero-row Hydrate yields a
// non-nil pointer to "").
func (j *launchdJob) persistTo(scope storage.Scope, store storage.Store) error {
	if j.d.Launchd == "" {
		return nil
	}
	if err := store.Put(scope, launchdCacheRowKey, j.d.Launchd); err != nil {
		return fmt.Errorf("launchd: persist: %w", err)
	}
	return nil
}

// launchdRenderer owns the per-task Markdown/HTML/JSON emission for the
// `### launchd Config` section. Render-time state is the rendered diff
// string stored on d.Launchd by [launchdJob.ProcessVolume].
type launchdRenderer struct {
	body string
}

func newLaunchdRenderer(body string) *launchdRenderer {
	return &launchdRenderer{body: body}
}

// JSONKey returns the stable JSON key that launchd payloads embed under
// in the top-level report DTO.
func (r *launchdRenderer) JSONKey() string { return "launchd" }

// Empty reports whether the section has nothing to render.
func (r *launchdRenderer) Empty() bool { return len(r.body) == 0 }

// Markdown emits the `### launchd Config` section. The byte sequence
// must remain identical to the prior inlined body in md.go.
func (r *launchdRenderer) Markdown(out *strings.Builder, _ string) error {
	if r.Empty() {
		return nil
	}
	out.WriteString("### launchd Config\n\n<details>\n  <summary><i>View Updated</i></summary>\n\n" + r.body + "\n\n</details>\n\n")
	return nil
}

// HTML returns the per-task HTML fragment for the `launchd Config`
// section. The fragment Body is the rendered markdown-to-HTML body
// preceded by the standard 10-space heading indent, matching the bytes
// the outer template previously emitted for this section.
func (r *launchdRenderer) HTML() (HTMLFragment, error) {
	if r.Empty() {
		return HTMLFragment{Heading: "launchd Config"}, nil
	}
	body := "\n          " + string(renderMarkdownFragment(r.body))
	return HTMLFragment{Heading: "launchd Config", Body: template.HTML(body)}, nil
}

// JSON returns the per-task report payload: the rendered launchd-diff
// string embedded under [launchdRenderer.JSONKey] in the top-level report
// DTO. Returns the underlying string as-is so buildReport's omitempty
// handling matches the legacy `Diff.Launchd` field encoding.
func (r *launchdRenderer) JSON() any {
	return r.body
}
