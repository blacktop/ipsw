package diff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/diff/storage"
)

// sandboxTask owns the sandbox-profile diff parse plus the per-renderer
// emission for the `### Sandbox Profiles` section. Parse wraps
// [Diff.parseSandboxProfiles] (build-tag gated; falls back to the stub
// path when the package is built without -tags sandbox).
type sandboxTask struct {
	d *Diff
}

func newSandboxTask(d *Diff) *sandboxTask {
	return &sandboxTask{d: d}
}

// Name returns the stable identifier used for logs and cache scoping.
func (t *sandboxTask) Name() string { return "sandbox" }

// JSONKey returns the stable public JSON key under which the task's
// payload embeds in the top-level report DTO.
func (t *sandboxTask) JSONKey() string { return "sandbox" }

// Empty reports whether the task has nothing to render.
func (t *sandboxTask) Empty() bool { return t.d.Sandbox == "" }

// Parse runs the sandbox-profile diff. Wraps the existing
// [Diff.parseSandboxProfiles] (gated by the sandbox build tag) and
// stores the rendered diff on d.Sandbox.
func (t *sandboxTask) Parse(_ context.Context, d *Diff) error {
	out, err := d.parseSandboxProfiles()
	if err != nil {
		return err
	}
	d.Sandbox = out
	return nil
}

// sandboxCacheVersion is the cache payload / output-semantics version for
// sandboxTask. Bump it whenever the persisted row layout (the rendered
// sandbox-diff string), the sandbox parse/normalize/render pipeline, or the
// rendered `### Sandbox Profiles` section semantics change in a way that
// invalidates rows written by a prior ipsw build.
const sandboxCacheVersion = 1

// Version reports the cache payload / output-semantics version. See
// sandboxCacheVersion.
func (t *sandboxTask) Version() int { return sandboxCacheVersion }

// OptionsHash digests every output-affecting option for sandboxTask. The task
// has no output-affecting flags: the `--sandbox` flag only toggles whether the
// task runs at all (it gates registration, not output), and parseSandboxProfiles
// always walks the fixed sandboxDiffSourceOrder (collection / protobox / platform
// profile) with the fixed normalize node/byte budgets, rendering through the
// fixed sandbox diff path. There are no allow/block lists, no verbosity, and no
// profile-selection flags. The only things that can change the rendered bytes are
// the parse/normalize/render logic itself (tracked by sandboxCacheVersion) and
// whether the binary was built with -tags sandbox at all (tracked by
// sandboxBuildTag): a stub build returns ErrSandboxDiffUnavailable and can never
// produce sandbox output, so folding the build tag keeps stub-build and
// sandbox-build runs on disjoint cache scopes. Without it a stub build sharing a
// --cache-dir with a sandbox build would hit (and hydrate) a sandbox row it could
// not itself produce, rendering a section out of thin air.
func (t *sandboxTask) OptionsHash() string {
	h := sha256.New()
	_, _ = h.Write([]byte("sandbox-options-v"))
	_, _ = h.Write([]byte{byte(sandboxCacheVersion)})
	_, _ = h.Write([]byte(sandboxBuildTag))
	_, _ = h.Write([]byte{0})
	return hex.EncodeToString(h.Sum(nil))
}

// InputHash digests the task-scope inputs: the old and new BuildManifest
// KernelCache digests, folded over sorted models, old then new. The sandbox
// profiles are read entirely from the kernelcache Mach-O
// (collectSandboxProfileDocuments opens ctx.Kernel.Path and parses the embedded
// collection / protobox / platform-profile blobs), so it shares the kexts
// InputHash source (kernelcacheDMGInputHash) — the same digest source the
// sameKernel short-circuit inspects. No DSC dylib or other artifact is read, so
// nothing else is folded.
func (t *sandboxTask) InputHash() string {
	return kernelcacheDMGInputHash(t.d.Old.Info, t.d.New.Info)
}

// sandboxCacheRowKey is the single row key for the cached sandbox-diff string.
const sandboxCacheRowKey = "sandbox"

// Hydrate rebuilds the sandbox-diff string from a cache hit. The single row
// holds the rendered string; the decoded value is published to d.Sandbox so
// rendering sees the cached state without re-parsing. A zero-row hit (the
// empty-result case, where parseSandboxProfiles found no profiles on either
// side) leaves d.Sandbox the empty string, so the hit path renders
// byte-identically to a fresh empty run.
func (t *sandboxTask) Hydrate(scope storage.Scope, store storage.Store) error {
	var out string
	err := store.Iter(scope, func(key string, decode func(v any) error) error {
		var s string
		if err := decode(&s); err != nil {
			return fmt.Errorf("sandbox: hydrate %s: %w", key, err)
		}
		out = s
		return nil
	})
	if err != nil {
		return err
	}
	t.d.Sandbox = out
	return nil
}

// persistTo writes the sandbox-diff string from the freshly-parsed Diff. It runs
// only after a successful Parse. An empty result (no profiles on either side)
// writes zero rows so a later zero-row Hydrate leaves d.Sandbox the empty string,
// matching a fresh empty run.
func (t *sandboxTask) persistTo(scope storage.Scope, store storage.Store) error {
	if t.Empty() {
		return nil
	}
	if err := store.Put(scope, sandboxCacheRowKey, t.d.Sandbox); err != nil {
		return fmt.Errorf("sandbox: persist: %w", err)
	}
	return nil
}

// Markdown emits the sandbox sub-section. The byte sequence must remain
// identical to the prior inlined body in md.go: writes the inline link
// into the README and the dedicated Sandbox.md side-effect file under
// outputDir.
func (t *sandboxTask) Markdown(w *strings.Builder, outputDir string) error {
	if t.Empty() {
		return nil
	}
	w.WriteString("### Sandbox Profiles\n\n")
	fname := filepath.Join(outputDir, "Sandbox.md")
	log.Debugf("Creating diff Sandbox Markdown: %s", fname)
	f, err := os.Create(fname)
	if err != nil {
		return fmt.Errorf("failed to create diff Sandbox Markdown: %w", err)
	}
	fmt.Fprintf(f, "## Sandbox Profiles\n\n")
	fmt.Fprintf(f, "%s", t.d.Sandbox)
	f.Close()
	w.WriteString(fmt.Sprintf("- [%s](%s)\n\n", "Sandbox Profiles DIFF", "Sandbox.md"))
	return nil
}

// HTML returns the per-task HTML fragment Body for the `Sandbox Profiles`
// section. Mirrors the outer template slice it replaces:
//
//	{{- if .Sandbox }}
//	<h2 id="sandbox-profiles">Sandbox Profiles</h2>
//	{{ .Sandbox }}
//	{{- end }}
//
// The leading "\n          " ensures the outer
// `{{- if not .SandboxFragment.Empty }}{{ .SandboxFragment.Body }}{{- end }}`
// splice produces byte-identical output.
func (t *sandboxTask) HTML() (HTMLFragment, error) {
	if t.Empty() {
		return HTMLFragment{Heading: "Sandbox Profiles"}, nil
	}
	rendered := renderMarkdownFragment(t.d.Sandbox)
	body := template.HTML("\n          <h2 id=\"sandbox-profiles\">Sandbox Profiles</h2>\n          " + string(rendered))
	return HTMLFragment{Heading: "Sandbox Profiles", Body: body}, nil
}

// JSON returns the per-task report payload: the rendered sandbox-diff
// string embedded under [sandboxTask.JSONKey] in the top-level report
// DTO. Returns the underlying string as-is so buildReport's omitempty
// handling matches the legacy `Diff.Sandbox` field encoding.
func (t *sandboxTask) JSON() any {
	return t.d.Sandbox
}

// Compile-time assertions: sandboxTask satisfies the top-level task lifecycle
// and the cache contract; its render surface mirrors the per-section renderers.
var (
	_ TopLevelTask  = (*sandboxTask)(nil)
	_ CacheableTask = (*sandboxTask)(nil)
)
