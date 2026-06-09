package diff

import (
	"context"
	"fmt"
	"strings"

	"github.com/blacktop/ipsw/internal/diff/storage"
)

// ibootTask owns the iBoot parse plus the per-renderer emission for the
// `### iBoot` section. Parse wraps the existing [Diff.parseIBoot] so
// per-mode behavior (OTA / IPSW) is unchanged.
type ibootTask struct {
	d *Diff

	// hydrated holds the IBootDiff loaded from a cache hit. Non-nil only on
	// the hydrate path; Hydrate publishes it directly to d.IBoot and the
	// orchestrator skips Parse. A zero-content hit yields a non-nil empty
	// IBootDiff so the hydrate branch is still taken.
	hydrated *IBootDiff
}

func newIBootTask(d *Diff) *ibootTask {
	return &ibootTask{d: d}
}

// Name returns the stable identifier used for logs and cache scoping.
func (t *ibootTask) Name() string { return "iboot" }

// JSONKey returns the stable public JSON key under which the task's
// payload embeds in the top-level report DTO.
func (t *ibootTask) JSONKey() string { return "iboot" }

// Empty reports whether the task has nothing to render.
func (t *ibootTask) Empty() bool {
	if t.d.IBoot == nil {
		return true
	}
	return len(t.d.IBoot.Versions) < 2 && len(t.d.IBoot.New) == 0 && len(t.d.IBoot.Removed) == 0
}

// Parse runs the iBoot enumeration. Wraps the existing [Diff.parseIBoot]
// so per-mode behavior (OTA / IPSW) is unchanged. Skipped by the
// orchestrator on a cache hit (Hydrate publishes the result).
func (t *ibootTask) Parse(_ context.Context, d *Diff) error {
	return d.parseIBoot()
}

// ibootCacheVersion is the cache payload / output-semantics version for
// ibootTask. Bump it whenever the persisted row layout (the IBootDiff), the
// iBoot string-diff logic, or the rendered iBoot section semantics change in a
// way that invalidates rows written by a prior ipsw build.
const ibootCacheVersion = 1

// Version reports the cache payload / output-semantics version. See
// ibootCacheVersion.
func (t *ibootTask) Version() int { return ibootCacheVersion }

// OptionsHash digests every output-affecting option for ibootTask. The task has
// no output-affecting flags: parseIBoot always extracts the iBoot strings,
// diffs them with the fixed 10-char minimum-length filter, and renders them
// through the fixed ibootTask render path. There are no allow/block lists, no
// verbosity, and no diff-tool selection. The only thing that can change the
// rendered bytes is the parse/diff/render logic itself, tracked by
// ibootCacheVersion, so the hash folds in that constant version tag alone.
func (t *ibootTask) OptionsHash() string {
	return constOptionsHash("iboot-options-v", ibootCacheVersion)
}

// InputHash digests the task-scope inputs: every distinct "iBoot" BuildManifest
// entry digest, sorted, old then new. parseIBoot reads the iBoot im4p straight
// from the IPSW zip (the first member matching iBoot\..*\.im4p), so there is no
// single manifest path to key on; folding every iBoot manifest digest tracks
// any change to the iBoot firmware artifact regardless of which per-device
// variant the zip yields.
func (t *ibootTask) InputHash() string {
	return ibootDMGInputHash(t.d.Old.Info, t.d.New.Info)
}

// ibootCacheRowKey is the single row key for the cached IBootDiff.
const ibootCacheRowKey = "iboot"

// Hydrate rebuilds the IBootDiff from a cache hit. The single row holds a
// gob-encoded IBootDiff; the decoded value is stashed in t.hydrated and
// published to d.IBoot so rendering sees the cached state without re-parsing. A
// zero-row hit (the empty-result case) yields a non-nil empty IBootDiff so the
// hydrate branch is still taken and publishes byte-identical empty output.
func (t *ibootTask) Hydrate(scope storage.Scope, store storage.Store) error {
	out := &IBootDiff{
		New:     make(map[string][]string),
		Removed: make(map[string][]string),
	}
	err := store.Iter(scope, func(key string, decode func(v any) error) error {
		var diff IBootDiff
		if err := decode(&diff); err != nil {
			return fmt.Errorf("iboot: hydrate %s: %w", key, err)
		}
		out = &diff
		return nil
	})
	if err != nil {
		return err
	}
	t.hydrated = out
	t.d.IBoot = out
	return nil
}

// persistTo writes the IBootDiff from the freshly-parsed Diff. It runs only
// after a successful Parse. An empty result (no version pair and no new/removed
// strings) writes zero rows so a later zero-row Hydrate yields a non-nil empty
// IBootDiff and renders byte-identically to a fresh empty run.
func (t *ibootTask) persistTo(scope storage.Scope, store storage.Store) error {
	if t.Empty() {
		return nil
	}
	if err := store.Put(scope, ibootCacheRowKey, t.d.IBoot); err != nil {
		return fmt.Errorf("iboot: persist: %w", err)
	}
	return nil
}

// Markdown emits the iBoot section. New/Removed render as a list of changed
// bins, each linking to a side-car markdown doc under IBOOT/ that holds that
// bin's changed strings, under the shared plain/collapsed/spill rule.
func (t *ibootTask) Markdown(w *strings.Builder, outputDir string) error {
	if t.d.IBoot == nil {
		return nil
	}
	if len(t.d.IBoot.Versions) >= 2 {
		fmt.Fprintf(w,
			"### iBoot\n\n"+
				"| iOS | Version |\n"+
				"| :-- | :------ |\n"+
				"| %s *(%s)* | %s |\n"+
				"| %s *(%s)* | %s |\n\n",
			t.d.Old.Version, t.d.Old.Build, t.d.IBoot.Versions[0],
			t.d.New.Version, t.d.New.Build, t.d.IBoot.Versions[1],
		)
	}
	if err := renderBinStringList(w, listSection{headingPrefix: "####", title: "🆕 NEW", tag: "NEW", subDir: "IBOOT", label: "iBoot", groupDir: "NEW"}, t.d.IBoot.New, outputDir); err != nil {
		return err
	}
	return renderBinStringList(w, listSection{headingPrefix: "####", title: "❌ Removed", tag: "Removed", subDir: "IBOOT", label: "iBoot", groupDir: "Removed"}, t.d.IBoot.Removed, outputDir)
}

// ibootHTMLTemplate renders the iBoot HTML body the outer page template
// previously emitted between
//
//	{{- if .IBoot }}
//
// and
//
//	{{- end }}
//
// The leading "\n          " ensures the outer
// `{{- if not .IBootFragment.Empty }}{{ .IBootFragment.Body }}{{- end }}`
// splice produces byte-identical output.
const ibootHTMLTemplate = `
          <h2 id="iboot">iBoot</h2>
          {{- if ge (len .IBoot.Versions) 2 }}
          <table>
            <caption>iBoot version comparison across the old and new inputs.</caption>
            <thead><tr><th>iOS</th><th>Version</th></tr></thead>
            <tbody>
              <tr><td>{{ .OldVersion }} <em>({{ .OldBuild }})</em></td><td>{{ index .IBoot.Versions 0 }}</td></tr>
              <tr><td>{{ .NewVersion }} <em>({{ .NewBuild }})</em></td><td>{{ index .IBoot.Versions 1 }}</td></tr>
            </tbody>
          </table>
          {{- end }}
          {{- if .IBoot.New }}
          <h3 id="iboot-new">New</h3>
          <details>
            <summary>View New ({{ len .IBoot.New }})</summary>
            {{- range .IBoot.New }}
            <div class="diff-entry">
              <h4>{{ .Name }}</h4>
              <ul>{{ range .Items }}<li><code>{{ . }}</code></li>{{ end }}</ul>
            </div>
            {{- end }}
          </details>
          {{- end }}
          {{- if .IBoot.Removed }}
          <h3 id="iboot-removed">Removed</h3>
          <details>
            <summary>View Removed ({{ len .IBoot.Removed }})</summary>
            {{- range .IBoot.Removed }}
            <div class="diff-entry">
              <h4>{{ .Name }}</h4>
              <ul>{{ range .Items }}<li><code>{{ . }}</code></li>{{ end }}</ul>
            </div>
            {{- end }}
          </details>
          {{- end }}`

// ibootHTMLData is the input shape ibootHTMLTemplate expects: the
// converted IBoot diff plus the old/new version + build strings the
// version table needs.
type ibootHTMLData struct {
	IBoot      *htmlIBootDiff
	OldVersion string
	OldBuild   string
	NewVersion string
	NewBuild   string
}

// HTML returns the per-task HTML fragment Body for the `iBoot` section.
func (t *ibootTask) HTML() (HTMLFragment, error) {
	ib := convertIBootDiff(t.d.IBoot)
	if ib == nil {
		return HTMLFragment{Heading: "iBoot"}, nil
	}
	data := ibootHTMLData{
		IBoot:      ib,
		OldVersion: t.d.Old.Version,
		OldBuild:   t.d.Old.Build,
		NewVersion: t.d.New.Version,
		NewBuild:   t.d.New.Build,
	}
	body, err := executeHTMLTaskTemplate("iboot-html", ibootHTMLTemplate, data)
	if err != nil {
		return HTMLFragment{}, err
	}
	return HTMLFragment{Heading: "iBoot", Body: body}, nil
}

// JSON returns the per-task report payload: the [IBootDiff] embedded
// under [ibootTask.JSONKey] in the top-level report DTO. Returns the
// underlying pointer as-is so buildReport's omitempty handling matches
// the legacy `Diff.IBoot` field encoding.
func (t *ibootTask) JSON() any {
	return t.d.IBoot
}

// Compile-time assertions: ibootTask satisfies the top-level task lifecycle and
// the cache contract; its render surface mirrors the per-section renderers.
var (
	_ TopLevelTask  = (*ibootTask)(nil)
	_ CacheableTask = (*ibootTask)(nil)
)
