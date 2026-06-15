package diff

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/blacktop/go-macho"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/signature"
)

// machosJob diffs Mach-Os across all four IPSW OS volumes. The job
// participates in the shared per-volume Mach-O walk via [MachoWalkTask],
// emitting a per-binary handler for each side that the orchestrator fans
// out alongside other tasks (entsJob, future signatures/strings jobs).
//
// All scan state is held on disk per volume via mcmd.WriteCachedDiffInfo,
// so peak heap stays bounded regardless of how many binaries each volume
// contains. The previous in-memory mode (controlled by --low-memory=false)
// was removed because it pushed peak heap into double-digit GB on a
// realistic IPSW pair, which prevented running the diff in CI.
type machosJob struct {
	d    *Diff
	conf *mcmd.DiffConfig

	// volumes captures volume labels in insertion order so Finalize iterates
	// deterministically.
	volumes []string

	// cacheDir is the root that holds a sub-directory per volume; each
	// volume's sub-dir holds one gob-encoded DiffInfo file per binary.
	cacheDir string

	// volumeCacheDirs maps volume label to its per-binary DiffInfo cache
	// directory. Populated by BeginVolume so the per-side handler closures
	// can locate the right bucket without re-deriving paths.
	volumeCacheDirs map[string]string

	// prevKeysByVolume tracks which old-side paths were matched by a new-side
	// counterpart. Unmatched entries become Removed at Finalize.
	prevKeysByVolume map[string]map[string]bool

	// diffByVolume accumulates the rendered diff for each volume.
	diffByVolume map[string]*mcmd.MachoDiff

	// hydrated holds the per-volume MachoDiff result loaded from a cache hit.
	// Non-nil only on the hydrate path; Finalize publishes it directly to
	// j.d.Machos and skips the volume fold. The orchestrator excludes a
	// hydrated task from the volume walk, so the temp cacheDir stays empty.
	hydrated map[string]*mcmd.MachoDiff
}

var _ CacheableTask = (*machosJob)(nil)

func newMachosJob(d *Diff) *machosJob {
	return &machosJob{
		d:                d,
		conf:             d.machoDiffConfig(),
		volumeCacheDirs:  make(map[string]string),
		diffByVolume:     make(map[string]*mcmd.MachoDiff),
		prevKeysByVolume: make(map[string]map[string]bool),
	}
}

func (j *machosJob) Name() string { return "machos" }

func (j *machosJob) Needs(typ string) bool {
	switch typ {
	case "fs", "sys", "app", "exc":
		return true
	}
	return false
}

// Setup creates the on-disk cache dir that persists across every volume's
// scan. It is removed in Finalize. The within-run per-binary DiffInfo state
// lives in that temp dir, not the injected store; the store holds only the
// persistent per-volume result rows written by persistTo.
func (j *machosJob) Setup(storage.Store) error {
	cacheDir, err := os.MkdirTemp("", "ipsw_macho_diff_cache")
	if err != nil {
		return fmt.Errorf("failed to create macho diff cache dir: %w", err)
	}
	j.cacheDir = cacheDir
	return nil
}

// BeginVolume creates this volume's per-binary cache bucket and initializes
// the per-side bookkeeping. Called by the orchestrator before any handler
// runs for the volume.
func (j *machosJob) BeginVolume(typ string) error {
	label := volumeLabel(typ)
	trackVolumeOnce(&j.volumes, label)
	volumeCacheDir := filepath.Join(j.cacheDir, label)
	if err := os.MkdirAll(volumeCacheDir, 0o755); err != nil {
		return fmt.Errorf("failed to create cache dir for %s: %w", label, err)
	}
	j.volumeCacheDirs[label] = volumeCacheDir
	if j.prevKeysByVolume[label] == nil {
		j.prevKeysByVolume[label] = make(map[string]bool)
	}
	if j.diffByVolume[label] == nil {
		j.diffByVolume[label] = &mcmd.MachoDiff{Updated: make(map[string]string)}
	}
	return nil
}

// MachoHandler returns the per-binary closure for the requested side. The
// old-side closure caches the DiffInfo to disk and records the path so we
// can later detect removals; the new-side closure compares against the
// cached old-side DiffInfo and folds Updated/New entries into the
// per-volume MachoDiff.
func (j *machosJob) MachoHandler(typ string, side Side) MachoScanHandler {
	label := volumeLabel(typ)
	volumeCacheDir := j.volumeCacheDirs[label]
	prevKeys := j.prevKeysByVolume[label]
	diff := j.diffByVolume[label]

	switch side {
	case SideOld:
		return func(path string, m *macho.File) error {
			prevKeys[path] = false
			return mcmd.WriteCachedDiffInfo(volumeCacheDir, path, mcmd.GenerateDiffInfo(m, j.conf))
		}
	case SideNew:
		return func(path string, m *macho.File) error {
			matched, ok := prevKeys[path]
			if !ok {
				diff.New = append(diff.New, path)
				return nil
			}
			if matched {
				return nil
			}
			oldInfo, err := mcmd.ReadCachedDiffInfo(volumeCacheDir, path)
			if err != nil {
				return err
			}
			newInfo := mcmd.GenerateDiffInfo(m, j.conf)
			if newInfo.Equal(*oldInfo) {
				prevKeys[path] = true
				return nil
			}
			formatted, err := mcmd.FormatUpdatedDiff(oldInfo, newInfo, j.conf)
			if err != nil {
				return err
			}
			if formatted != "" {
				diff.Updated[path] = formatted
			}
			prevKeys[path] = true
			return nil
		}
	}
	return nil
}

// EndVolume is a no-op for machos: removed-path bookkeeping is folded in
// Finalize so a partially-disabled volume still produces consistent output
// for the remaining volumes.
func (j *machosJob) EndVolume(typ string) error { return nil }

// AbortVolume discards state for typ after a shared-walk handler failure. A
// partially scanned old side cannot be finalized safely because unmatched keys
// would be reported as removed even though the new-side comparison was skipped.
func (j *machosJob) AbortVolume(typ string) {
	label := volumeLabel(typ)
	delete(j.prevKeysByVolume, label)
	delete(j.diffByVolume, label)
	delete(j.volumeCacheDirs, label)
	removeVolume(&j.volumes, label)
	if j.cacheDir != "" {
		_ = os.RemoveAll(filepath.Join(j.cacheDir, label))
	}
}

// Finalize folds unmatched old-side paths into Removed and assembles
// the per-volume MachoDiff map on the Diff.
//
// Setup creates the temp cacheDir unconditionally (it runs before the cache
// hydration decision), so the cleanup defer must fire on BOTH paths or a
// cache hit leaks the dir. On the cache-hit path (j.hydrated non-nil) the
// orchestrator excluded the task from the volume walk, so there is no
// per-volume scan state to fold: publish the hydrated result directly.
func (j *machosJob) Finalize() error {
	defer func() {
		if j.cacheDir != "" {
			_ = os.RemoveAll(j.cacheDir)
			j.cacheDir = ""
		}
	}()

	if j.hydrated != nil {
		j.d.Machos = j.hydrated
		return nil
	}

	out := make(map[string]*mcmd.MachoDiff, len(j.volumes))
	for _, label := range j.volumes {
		diff := j.diffByVolume[label]
		if diff == nil {
			continue
		}
		for path, matched := range j.prevKeysByVolume[label] {
			if !matched {
				diff.Removed = append(diff.Removed, path)
			}
		}
		if machoDiffHasContent(diff) {
			out[label] = diff
		}
	}
	j.d.Machos = out
	j.prevKeysByVolume = nil
	j.diffByVolume = nil
	j.volumeCacheDirs = nil
	return nil
}

func machoDiffHasContent(d *mcmd.MachoDiff) bool {
	return d != nil && (len(d.New) > 0 || len(d.Removed) > 0 || len(d.Updated) > 0)
}

// machosCacheVersion is the cache payload / output-semantics version for
// machosJob. The diff cache shipped in v3.1.693, so bump this whenever the
// persisted row layout (per-volume MachoDiff), the InputHash composition, or
// the rendered MachO section semantics change in a way that invalidates rows
// written by a prior ipsw build.
const machosCacheVersion = 1

// Version reports the cache payload / output-semantics version. See
// machosCacheVersion.
func (j *machosJob) Version() int { return machosCacheVersion }

// OptionsHash digests every output-affecting input to the MachO diff so a
// rerun with different options cannot silently serve a stale rendered result.
// It folds in the allow-list, the block-list, and every field of the
// mcmd.DiffConfig the task renders with (j.conf). Cosmetic fields that do not
// change diff content are still included because DiffConfig.Markdown,
// DiffConfig.Color, and DiffConfig.DiffTool all change the rendered bytes
// (FormatUpdatedDiff fences/colors and the git diff tool selection).
//
// Folded fields:
//   - AllowList (sorted)
//   - BlockList (sorted)
//   - Markdown
//   - Color
//   - DiffTool
//   - CStrings   (--strs / cstrings section content)
//   - FuncStarts (--starts / func-starts section content)
//   - IgnoreLoadCommands (only when enabled; false is the legacy/default scope)
//   - PemDB      (signature PEM database path)
//   - SymMap     (signature symbol maps; sorted by map key then address)
//   - Verbose
//
// Known limitation (cross-host cache sharing only): DiffTool is hardcoded to
// "git" by machoDiffConfig, so FormatUpdatedDiff shells out to the host git
// binary (utils.createGitDiffPatch). The git *version* — not just the tool
// name — affects the rendered hunk/context bytes, and it is not folded here.
// This never breaks single-host idempotency or the parity invariant because
// the default cache lives under os.UserCacheDir() and is host-local. It only
// matters if a .db built on host A (git X) is copied to host B (git Y) via
// --cache-dir; host B would then serve host A's bytes. Treat the cache as
// host-bound rather than folding `git --version` into every scope build
// (which would add a subprocess to every run).
func (j *machosJob) OptionsHash() string {
	h := sha256.New()
	_, _ = h.Write([]byte("macho-walk-confines-absolute-symlinks-to-mount-root"))
	_, _ = h.Write([]byte{0})
	hashMachoDiffConfig(h, j.conf)
	return hex.EncodeToString(h.Sum(nil))
}

// hashMachoDiffConfig folds every output-affecting field of a mcmd.DiffConfig
// into h, deterministically (allow/block lists sorted, SymMap key/address
// sorted). It is shared by machosJob and dscJob: both render their MachO/dylib
// diff through a DiffConfig built from the same output-affecting knobs, so their
// OptionsHash must fold the exact same fields. See machosJob.OptionsHash for
// the rationale behind folding the cosmetic Markdown/Color/DiffTool fields
// (they change the rendered bytes) and the known DiffTool git-version
// cross-host limitation.
func hashMachoDiffConfig(h io.Writer, conf *mcmd.DiffConfig) {
	if conf == nil {
		_, _ = h.Write([]byte{0x00}) // stable absent-config marker
		return
	}
	// The cache stores rendered diff bodies, not DiffInfo. Fold fixed renderer
	// semantics here so rows rendered by older local builds do not hydrate into
	// reports after the text format changes.
	_, _ = h.Write([]byte("macho-report-hides-load-command-hash"))
	_, _ = h.Write([]byte{0})
	writeStringList := func(label string, items []string) {
		_, _ = h.Write([]byte(label))
		_, _ = h.Write([]byte{0})
		sorted := append([]string(nil), items...)
		slices.Sort(sorted)
		for _, s := range sorted {
			_, _ = h.Write([]byte(s))
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte{0xff})
	}
	writeBool := func(label string, v bool) {
		_, _ = h.Write([]byte(label))
		if v {
			_, _ = h.Write([]byte{1})
		} else {
			_, _ = h.Write([]byte{0})
		}
	}
	writeString := func(label, v string) {
		_, _ = h.Write([]byte(label))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(v))
		_, _ = h.Write([]byte{0})
	}

	writeStringList("AllowList", conf.AllowList)
	writeStringList("BlockList", conf.BlockList)
	writeBool("Markdown", conf.Markdown)
	writeBool("Color", conf.Color)
	writeString("DiffTool", conf.DiffTool)
	writeBool("CStrings", conf.CStrings)
	writeBool("FuncStarts", conf.FuncStarts)
	if conf.IgnoreLoadCommands {
		writeBool("IgnoreLoadCommands", true)
	}
	writeString("PemDB", conf.PemDB)
	writeSymMaps(h, conf.SymMap)
	writeBool("Verbose", conf.Verbose)
}

// writeSymMaps folds the signature symbol maps into h deterministically:
// outer keys sorted, then each map's addresses sorted, so two runs with the
// same logical map produce the same digest regardless of Go map iteration
// order. machoDiffConfig never sets SymMap today, so this is empty in
// practice; folding it keeps the hash correct if a future build wires it up.
func writeSymMaps(h io.Writer, maps map[string]signature.SymbolMap) {
	_, _ = h.Write([]byte("SymMap"))
	_, _ = h.Write([]byte{0})
	outer := make([]string, 0, len(maps))
	for k := range maps {
		outer = append(outer, k)
	}
	slices.Sort(outer)
	for _, name := range outer {
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		sm := maps[name]
		addrs := make([]uint64, 0, len(sm))
		for addr := range sm {
			addrs = append(addrs, addr)
		}
		slices.Sort(addrs)
		for _, addr := range addrs {
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], addr)
			_, _ = h.Write(b[:])
			_, _ = h.Write([]byte(sm[addr]))
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte{0xff})
	}
}

// InputHash digests the task-scope inputs: the old and new BuildManifest DMG
// digests for every volume machosJob reads (fs/sys/app/exc). It delegates to
// volumeDMGInputHash, the shared per-volume fingerprint that entsJob also uses,
// because both jobs walk the identical four volumes.
func (j *machosJob) InputHash() string {
	return volumeDMGInputHash(j.d.Old.Info, j.d.New.Info)
}

// machosCacheRowKey is the row key for a volume's cached MachoDiff. The key is
// the volume label so a hydrate can rebuild the per-volume map directly.
func machosCacheRowKey(label string) string { return label }

// Hydrate rebuilds the per-volume MachoDiff result from a cache hit. Each row
// is keyed by volume label and holds a gob-encoded *mcmd.MachoDiff. The
// decoded map is stashed in j.hydrated for Finalize to publish; the volume
// walk is skipped entirely by the orchestrator.
func (j *machosJob) Hydrate(scope storage.Scope, store storage.Store) error {
	out := make(map[string]*mcmd.MachoDiff)
	err := store.Iter(scope, func(key string, decode func(v any) error) error {
		var diff mcmd.MachoDiff
		if err := decode(&diff); err != nil {
			return fmt.Errorf("machos: hydrate %s: %w", key, err)
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

// persistTo writes one row per volume label from the freshly-computed result.
// It runs only after a successful fresh walk + Finalize, so it reads from
// j.d.Machos (the published result) rather than j.diffByVolume, which Finalize
// has already cleared.
func (j *machosJob) persistTo(scope storage.Scope, store storage.Store) error {
	for label, diff := range j.d.Machos {
		if err := store.Put(scope, machosCacheRowKey(label), diff); err != nil {
			return fmt.Errorf("machos: persist %s: %w", label, err)
		}
	}
	return nil
}

// machosRenderer owns the per-task Markdown/HTML/JSON emission for the
// `## MachO` section. The render-time state is the per-volume MachoDiff
// map produced by [machosJob.Finalize]; the renderer is constructed by
// [Diff.Markdown] from d.Machos because the job itself is destroyed
// after Finalize.
type machosRenderer struct {
	volumes map[string]*mcmd.MachoDiff
}

func newMachosRenderer(volumes map[string]*mcmd.MachoDiff) *machosRenderer {
	return &machosRenderer{volumes: volumes}
}

// JSONKey returns the stable JSON key that machos payloads embed under in
// the top-level report DTO.
func (r *machosRenderer) JSONKey() string { return "machos" }

// Empty reports whether the section has no rendered content and the
// orchestrator should skip the heading entirely.
func (r *machosRenderer) Empty() bool { return !hasMachoDiffVolumeContent(r.volumes) }

// Markdown emits the `## MachO` section body, including the section
// heading and the per-volume `### {volume}` sub-headings. Empty volumes
// are skipped. The byte sequence must remain identical to the prior
// inlined body in md.go.
func (r *machosRenderer) Markdown(out *strings.Builder, outputDir string) error {
	if r.Empty() {
		return nil
	}
	out.WriteString("## MachO\n\n")
	for _, vol := range sortedVolumeKeys(r.volumes) {
		diff := r.volumes[vol]
		if !machoDiffHasContent(diff) {
			continue
		}
		fmt.Fprintf(out, "### %s\n\n", vol)
		if err := renderMachoDiff(out, listSection{headingPrefix: "####", subDir: "MACHOS", label: vol, groupDir: vol}, diff, outputDir); err != nil {
			return err
		}
	}
	return nil
}

// machosHTMLTemplate renders the per-volume MachOs body. It must produce
// bytes identical to the slice of diffHTMLPageTemplate it replaces.
const machosHTMLTemplate = `
{{- range . }}
          <h3 id="machos-{{ .Name | slug }}">{{ .Name }}</h3>
          {{- template "machoDiffSection" dict "Prefix" (printf "machos-%s" (.Name | slug)) "Diff" .Diff }}
{{- end }}`

// HTML returns the per-task HTML fragment for the `MachOs` section. The
// fragment Body excludes the section's <h2> heading; renderHTML wraps the
// returned body with the section anchor and heading.
func (r *machosRenderer) HTML() (HTMLFragment, error) {
	volumes := convertMachoVolumeDiff(r.volumes)
	if len(volumes) == 0 {
		return HTMLFragment{Heading: "MachOs"}, nil
	}
	body, err := executeHTMLTaskTemplate("machos-html", machosHTMLTemplate, volumes)
	if err != nil {
		return HTMLFragment{}, err
	}
	return HTMLFragment{Heading: "MachOs", Body: body}, nil
}

// JSON returns the per-task report payload: the per-volume MachoDiff map
// embedded under [machosRenderer.JSONKey] in the top-level report DTO.
// Returns the underlying map as-is so buildReport's omitempty handling
// matches the legacy `Diff.Machos` field encoding (nil/empty maps drop the
// key entirely).
func (r *machosRenderer) JSON() any {
	return r.volumes
}
