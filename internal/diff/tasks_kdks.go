package diff

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/diff/storage"
)

// kdksTask owns the KDK structure diff parse plus the per-renderer
// emission for the `### KDKs` sub-section. Parse wraps the existing
// [Diff.parseKDKs] so the dwarf-structures pipeline is unchanged.
type kdksTask struct {
	d *Diff
}

func newKDKsTask(d *Diff) *kdksTask {
	return &kdksTask{d: d}
}

// Name returns the stable identifier used for logs and cache scoping.
func (t *kdksTask) Name() string { return "kdks" }

// JSONKey returns the stable public JSON key under which the task's
// payload embeds in the top-level report DTO.
func (t *kdksTask) JSONKey() string { return "kdks" }

// Empty reports whether the task has nothing to render.
func (t *kdksTask) Empty() bool { return t.d.KDKs == "" }

// Parse runs the KDK structures diff. Wraps the existing [Diff.parseKDKs]
// so the dwarf parse + markdown rendering pipeline is unchanged.
func (t *kdksTask) Parse(_ context.Context, d *Diff) error {
	return d.parseKDKs()
}

// kdksCacheVersion is the cache payload / output-semantics version for
// kdksTask. Bump it whenever the persisted row layout (the rendered KDK-diff
// string), the dwarf-structures diff pipeline, or the rendered `### KDKs`
// sub-section semantics change in a way that invalidates rows written by a prior
// ipsw build.
const kdksCacheVersion = 1

// Version reports the cache payload / output-semantics version. See
// kdksCacheVersion.
func (t *kdksTask) Version() int { return kdksCacheVersion }

// OptionsHash digests every output-affecting option for kdksTask. The task has
// no output-affecting flags: parseKDKs always renders the dwarf-structures diff
// with the fixed dwarf.Config (Markdown=true, Color=false, DiffTool="git"). There
// are no allow/block lists, no verbosity, and no diff-tool selection. The only
// thing that can change the rendered bytes is the parse/diff/render logic itself,
// tracked by kdksCacheVersion, so the hash folds in that constant version tag
// alone.
func (t *kdksTask) OptionsHash() string {
	return constOptionsHash("kdks-options-v", kdksCacheVersion)
}

// kdkDwarfPath resolves a user-passed --kdk path to the dSYM DWARF binary that
// dwarf.DiffStructures actually reads. parseKDKs rewrites the raw --kdk path
// (a kernel stub Mach-O, e.g. .../Kernels/kernel.release.t6000) to its sibling
// dSYM DWARF binary (.../kernel.release.t6000.dSYM/Contents/Resources/DWARF/
// kernel.release.t6000) before diffing, so the bytes that drive the diff live in
// that dSYM, NOT the stub. InputHash must stat the same resolved file or it
// fingerprints the wrong artifact (the stub is ~16 MB; the dSYM DWARF is ~75 MB).
// A path already pointing inside a DWARF dir is returned unchanged; an empty path
// stays empty so the inert no-KDK case is never transformed or stat'd.
func kdkDwarfPath(path string) string {
	if path == "" || strings.Contains(path, ".dSYM/Contents/Resources/DWARF") {
		return path
	}
	return filepath.Join(path+".dSYM/Contents/Resources/DWARF", filepath.Base(path))
}

// kdkDisplayPath normalizes a KDK path to the display form parseKDKs
// publishes on d.Old.KDK / d.New.KDK after diffing (and that the KDK.md
// renderer embeds): the KDK-relative stub path with the
// /Library/Developer/KDKs/ prefix and any dSYM DWARF suffix stripped, e.g.
// "KDK_26.0_25A5279m.kdk/System/Library/Kernels/kernel.release.t6000".
// Idempotent, so it is safe on raw CLI paths AND already-normalized ones.
// kdksTask.Hydrate applies it too: a warm hit skips parseKDKs, and without
// the normalization the cached KDK.md would embed the raw CLI paths and
// differ from a cold run's output.
func kdkDisplayPath(path string) string {
	path = strings.TrimPrefix(kdkDwarfPath(path), "/Library/Developer/KDKs/")
	path, _, _ = strings.Cut(path, ".dSYM/Contents/Resources/DWARF")
	return path
}

// kdkFileIdentity returns a cheap content identity for the KDK file at path: its
// size and modification time. It is a package var so tests can substitute a fake
// without writing real KDK files (which are multi-GB dSYM DWARF binaries). ok is
// false when the path does not resolve to a regular file.
//
// The identity is deliberately cheap (stat, not a full content hash): a KDK dSYM
// DWARF binary is multiple gigabytes, and hashing both sides on every run would
// dominate the diff. Limitation: size + mtime can collide if a KDK is replaced
// in place with a same-size build and its mtime is reset (e.g. via `touch -r` or
// a tar extraction preserving timestamps). In practice KDKs are versioned,
// immutable installs under /Library/Developer/KDKs, so a content change moves the
// path (a new KDK version) or the mtime (a fresh install); a same-path,
// same-size, same-mtime replacement is treated as unchanged. Bump kdksCacheVersion
// or pass a fresh --cache-dir if a stale KDK result is ever observed.
var kdkFileIdentity = func(path string) (size int64, modTimeUnixNano int64, ok bool) {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return 0, 0, false
	}
	return fi.Size(), fi.ModTime().UnixNano(), true
}

// InputHash digests the EXTERNAL KDK inputs: the user-passed d.Old.KDK and
// d.New.KDK filesystem paths plus, for each side, the cheap content identity
// (size + mtime via kdkFileIdentity) of the dSYM DWARF binary the diff actually
// reads — NOT the raw --kdk stub path. parseKDKs rewrites the stub path to its
// sibling dSYM DWARF binary before dwarf.DiffStructures reads it, so InputHash
// resolves the same dSYM via kdkDwarfPath and stats THAT file; statting the stub
// would fingerprint the wrong artifact (the stub is ~16 MB, the dSYM ~75 MB) and
// miss any debug-info change that leaves the stub untouched. KDKs are NOT read
// from the IPSW — they are loose files on disk the user supplies with --kdk — so
// no BuildManifest digest covers them. The raw path is also folded so pointing at
// a different KDK version moves the hash even if two dSYMs share a size+mtime.
// When a KDK path is empty (no --kdk passed), kdksTask is inert and Parse
// produces nothing; an empty path folds a stable absent marker and is never
// stat'd, so the hash is deterministic for the inert case. See kdkFileIdentity
// for the cheap-identity rationale and its same-size/same-mtime collision
// limitation.
func (t *kdksTask) InputHash() string {
	h := sha256.New()
	writeKDKIdentity(h, "old", t.d.Old.KDK)
	writeKDKIdentity(h, "new", t.d.New.KDK)
	return hex.EncodeToString(h.Sum(nil))
}

// writeKDKIdentity folds one side's raw KDK path plus the cheap file identity of
// the resolved dSYM DWARF binary into h. The raw path is folded so a different
// KDK version moves the hash; the identity is taken from kdkDwarfPath(path) — the
// exact file dwarf.DiffStructures reads — so a debug-info change is never missed.
// An empty path (no --kdk) or an unresolvable file writes a stable absent marker
// so the inert case is deterministic and two runs without --kdk agree.
func writeKDKIdentity(h io.Writer, side, path string) {
	_, _ = h.Write([]byte(side))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(path))
	_, _ = h.Write([]byte{0})
	if path == "" {
		_, _ = h.Write([]byte{0x00}) // absent marker
		return
	}
	size, modTime, ok := kdkFileIdentity(kdkDwarfPath(path))
	if !ok {
		_, _ = h.Write([]byte{0x00}) // absent marker
		return
	}
	_, _ = h.Write([]byte{0x01}) // present marker
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(size))
	binary.BigEndian.PutUint64(b[8:], uint64(modTime))
	_, _ = h.Write(b[:])
}

// kdksCacheRowKey is the single row key for the cached KDK-diff string.
const kdksCacheRowKey = "kdks"

// Hydrate rebuilds the KDK-diff string from a cache hit. The single row holds
// the rendered string; the decoded value is published to d.KDKs so rendering
// sees the cached state without re-parsing. A zero-row hit (the empty-result
// case, where no --kdk was passed or the structures matched) leaves d.KDKs the
// empty string, so the hit path renders byte-identically to a fresh empty run.
//
// The KDK.md side-effect file embeds d.Old.KDK / d.New.KDK, which parseKDKs
// normalizes to display form as a side effect. A warm hit skips Parse, so
// Hydrate applies the same kdkDisplayPath normalization here — otherwise the
// cached run's KDK.md would embed the raw CLI paths and differ from a cold
// run with identical inputs.
func (t *kdksTask) Hydrate(scope storage.Scope, store storage.Store) error {
	var out string
	err := store.Iter(scope, func(key string, decode func(v any) error) error {
		var s string
		if err := decode(&s); err != nil {
			return fmt.Errorf("kdks: hydrate %s: %w", key, err)
		}
		out = s
		return nil
	})
	if err != nil {
		return err
	}
	t.d.KDKs = out
	t.d.Old.KDK = kdkDisplayPath(t.d.Old.KDK)
	t.d.New.KDK = kdkDisplayPath(t.d.New.KDK)
	return nil
}

// persistTo writes the KDK-diff string from the freshly-parsed Diff. It runs only
// after a successful Parse. An empty result (no --kdk passed, or the dwarf
// structures matched) writes zero rows so a later zero-row Hydrate leaves d.KDKs
// the empty string, matching a fresh empty run.
func (t *kdksTask) persistTo(scope storage.Scope, store storage.Store) error {
	if t.Empty() {
		return nil
	}
	if err := store.Put(scope, kdksCacheRowKey, t.d.KDKs); err != nil {
		return fmt.Errorf("kdks: persist: %w", err)
	}
	return nil
}

// Markdown emits the KDKs sub-section. The byte sequence must remain
// identical to the prior inlined body in md.go: writes the inline link
// into the README and the dedicated KDK.md side-effect file under
// outputDir.
func (t *kdksTask) Markdown(w *strings.Builder, outputDir string) error {
	if t.Empty() {
		return nil
	}
	w.WriteString("### KDKs\n\n")
	fname := filepath.Join(outputDir, "KDK.md")
	log.Debugf("Creating diff KDK Markdown: %s", fname)
	f, err := os.Create(fname)
	if err != nil {
		return fmt.Errorf("failed to create diff KDK Markdown: %w", err)
	}
	fmt.Fprintf(f, "## KDKs\n\n"+
		"- `%s`\n"+
		"- `%s`\n\n",
		t.d.Old.KDK, t.d.New.KDK,
	)
	fmt.Fprintf(f, "%s", t.d.KDKs)
	f.Close()
	w.WriteString(fmt.Sprintf("- [%s](%s)\n\n", "KDK DIFF", "KDK.md"))
	return nil
}

// HTML returns the per-task HTML fragment Body for the `KDKs` section.
// Mirrors the outer template slice it replaces:
//
//	{{- if .KDKs }}
//	<h2 id="kdks">KDKs</h2>
//	{{ .KDKs }}
//	{{- end }}
//
// The leading "\n          " (newline + 10-space indent) ensures the
// outer `{{- if not .KDKsFragment.Empty }}{{ .KDKsFragment.Body }}{{- end }}`
// splice produces byte-identical output.
func (t *kdksTask) HTML() (HTMLFragment, error) {
	if t.Empty() {
		return HTMLFragment{Heading: "KDKs"}, nil
	}
	rendered := renderMarkdownFragment(t.d.KDKs)
	body := template.HTML("\n          <h2 id=\"kdks\">KDKs</h2>\n          " + string(rendered))
	return HTMLFragment{Heading: "KDKs", Body: body}, nil
}

// JSON returns the per-task report payload: the rendered KDKs diff string
// embedded under [kdksTask.JSONKey] in the top-level report DTO. Returns
// the underlying string as-is so buildReport's omitempty handling matches
// the legacy `Diff.KDKs` field encoding.
func (t *kdksTask) JSON() any {
	return t.d.KDKs
}

// Compile-time assertions: kdksTask satisfies the top-level task lifecycle and
// the cache contract; its render surface mirrors the per-section renderers.
var (
	_ TopLevelTask  = (*kdksTask)(nil)
	_ CacheableTask = (*kdksTask)(nil)
)
