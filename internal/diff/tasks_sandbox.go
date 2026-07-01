package diff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"strings"

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

// Markdown emits the `## Sandbox Profiles` section. Each profile diff is
// written to its own SANDBOX/<source>/<profile>.md side-car through the shared
// renderSideCarEntries path (path-mirrored, collision-safe names plus the
// standard collapse/spill rule), so the README carries only a per-group list of
// links -- never the full profile bodies, which for a real collection diff can
// be tens of megabytes. The pre-rendered d.Sandbox string is re-parsed back
// into its source/group/profile structure so this stays independent of the
// build-tag-gated parse pipeline.
func (t *sandboxTask) Markdown(w *strings.Builder, outputDir string) error {
	if t.Empty() {
		return nil
	}
	report, err := parseSandboxMarkdown(t.d.Sandbox)
	if err != nil {
		return err
	}

	w.WriteString("## Sandbox Profiles\n\n")
	for _, source := range report.Sources {
		if source.Total() == 0 {
			continue
		}
		fmt.Fprintf(w, "### %s (%d)\n\n", source.Name, source.Total())
		for _, group := range sandboxMarkdownGroups {
			profiles := source.Groups[group.key]
			if len(profiles) == 0 {
				continue
			}
			bodies := make(map[string]string, len(profiles))
			for _, p := range profiles {
				bodies[p.Name] = p.Fence
			}
			sec := listSection{
				headingPrefix: "####",
				title:         group.title,
				tag:           group.tag,
				subDir:        sandboxMarkdownSidecarDir,
				label:         source.Name,
				groupDir:      source.Slug,
			}
			title := group.title
			if err := renderSideCarEntries(w, sec, bodies, outputDir, func(name, fence string) string {
				return fmt.Sprintf("## %s\n\n> Group: %s\n\n%s\n", name, title, fence)
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// sandboxMarkdownSidecarDir is the side-car directory holding per-profile
// sandbox diff documents.
const sandboxMarkdownSidecarDir = "SANDBOX"

// sandboxMarkdownGroups is the deterministic render order for the three profile
// groups, pairing the normalized parse key with the emoji title and filename
// tag used by the shared list renderer.
var sandboxMarkdownGroups = [...]struct{ key, title, tag string }{
	{"Added", "🆕 NEW", "NEW"},
	{"Removed", "❌ Removed", "Removed"},
	{"Updated", "⬆️ Updated", "Updated"},
}

// sandboxMarkdownReport is the structured form of the rendered sandbox-diff
// string: an ordered list of sources, each grouping its profiles by change.
type sandboxMarkdownReport struct {
	Sources []sandboxMarkdownSource
}

type sandboxMarkdownSource struct {
	Name   string
	Slug   string
	Groups map[string][]sandboxMarkdownProfile
}

// Total is the profile count across all groups in the source.
func (s sandboxMarkdownSource) Total() int {
	total := 0
	for _, profiles := range s.Groups {
		total += len(profiles)
	}
	return total
}

type sandboxMarkdownProfile struct {
	Name  string
	Fence string
}

// parseSandboxMarkdown re-parses the rendered sandbox-diff string (produced by
// renderSandboxProfileDiffMarkdown) back into its source/group/profile
// structure. It tolerates either group naming (New/Added, Changed/Updated) and
// requires each profile to carry one complete fenced block. It errors on any
// content it cannot place so a renderer change never silently drops profiles.
func parseSandboxMarkdown(body string) (sandboxMarkdownReport, error) {
	lines := strings.Split(body, "\n")
	report := sandboxMarkdownReport{}
	sourceIndex := -1
	currentGroup := ""
	currentProfile := ""
	var profileLines []string
	inFence := false

	flushProfile := func() error {
		if currentProfile == "" {
			return nil
		}
		fence := strings.TrimSpace(strings.Join(profileLines, "\n"))
		if !strings.HasPrefix(fence, "```") || !sandboxMarkdownFenceComplete(profileLines) {
			return fmt.Errorf("sandbox markdown profile %q has an incomplete fenced block", currentProfile)
		}
		report.Sources[sourceIndex].Groups[currentGroup] = append(
			report.Sources[sourceIndex].Groups[currentGroup],
			sandboxMarkdownProfile{Name: currentProfile, Fence: fence},
		)
		currentProfile = ""
		profileLines = nil
		inFence = false
		return nil
	}

	for lineNumber, line := range lines {
		for {
			if currentProfile != "" {
				if !inFence && sandboxMarkdownIsHeader(line) {
					if err := flushProfile(); err != nil {
						return sandboxMarkdownReport{}, err
					}
				} else {
					profileLines = append(profileLines, line)
					if strings.HasPrefix(strings.TrimSpace(line), "```") {
						inFence = !inFence
					}
					break
				}
			}

			if sourceName, ok := parseSandboxSourceHeader(line); ok {
				if err := flushProfile(); err != nil {
					return sandboxMarkdownReport{}, err
				}
				report.Sources = append(report.Sources, sandboxMarkdownSource{
					Name:   sourceName,
					Slug:   sandboxMarkdownSourceSlug(sourceName),
					Groups: make(map[string][]sandboxMarkdownProfile),
				})
				sourceIndex = len(report.Sources) - 1
				currentGroup = ""
				break
			}

			if groupName, ok := parseSandboxGroupHeader(line); ok {
				if sourceIndex < 0 {
					return sandboxMarkdownReport{}, fmt.Errorf("sandbox markdown group before source at line %d", lineNumber+1)
				}
				group, ok := normalizeSandboxMarkdownGroup(groupName)
				if !ok {
					return sandboxMarkdownReport{}, fmt.Errorf("sandbox markdown unsupported group %q at line %d", groupName, lineNumber+1)
				}
				currentGroup = group
				break
			}

			if profileName, ok := parseSandboxProfileHeader(line); ok {
				if sourceIndex < 0 || currentGroup == "" {
					return sandboxMarkdownReport{}, fmt.Errorf("sandbox markdown profile before group at line %d", lineNumber+1)
				}
				currentProfile = profileName
				profileLines = nil
				inFence = false
				break
			}

			if strings.TrimSpace(line) != "" {
				return sandboxMarkdownReport{}, fmt.Errorf("sandbox markdown unexpected content at line %d", lineNumber+1)
			}
			break
		}
	}

	if err := flushProfile(); err != nil {
		return sandboxMarkdownReport{}, err
	}
	if !report.HasProfiles() {
		return sandboxMarkdownReport{}, fmt.Errorf("sandbox markdown has no profiles")
	}
	return report, nil
}

// HasProfiles reports whether any source carries at least one profile.
func (r sandboxMarkdownReport) HasProfiles() bool {
	for _, source := range r.Sources {
		if source.Total() > 0 {
			return true
		}
	}
	return false
}

func sandboxMarkdownIsHeader(line string) bool {
	return strings.HasPrefix(line, "### ") ||
		strings.HasPrefix(line, "#### ") ||
		strings.HasPrefix(line, "##### ")
}

func parseSandboxSourceHeader(line string) (string, bool) {
	if !strings.HasPrefix(line, "### ") {
		return "", false
	}
	name := strings.TrimSpace(strings.TrimPrefix(line, "### "))
	return name, name != ""
}

func parseSandboxGroupHeader(line string) (string, bool) {
	if !strings.HasPrefix(line, "#### ") {
		return "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "#### "))
	idx := strings.LastIndex(rest, " (")
	if idx >= 0 && strings.HasSuffix(rest, ")") {
		rest = rest[:idx]
	}
	group := strings.TrimSpace(rest)
	return group, group != ""
}

func parseSandboxProfileHeader(line string) (string, bool) {
	if !strings.HasPrefix(line, "##### ") {
		return "", false
	}
	name := strings.TrimSpace(strings.TrimPrefix(line, "##### "))
	return name, name != ""
}

func normalizeSandboxMarkdownGroup(group string) (string, bool) {
	switch group {
	case "Removed":
		return "Removed", true
	case "Added", "New":
		return "Added", true
	case "Updated", "Changed":
		return "Updated", true
	default:
		return "", false
	}
}

func sandboxMarkdownFenceComplete(lines []string) bool {
	fences := 0
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fences++
		}
	}
	return fences >= 2 && fences%2 == 0
}

// sandboxMarkdownSourceSlug turns a source title into a stable side-car
// sub-directory name.
func sandboxMarkdownSourceSlug(source string) string {
	if source == "Platform Profile" {
		return "Platform"
	}
	slug := strings.NewReplacer("/", "-", " ", "-").Replace(source)
	slug = strings.Trim(slug, "-")
	if slug == "" {
		return "Source"
	}
	return slug
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
