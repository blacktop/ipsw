package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
)

// filesJob diffs the set of file paths inside an IPSW. Inputs scanned:
//
//   - The IPSW zip itself (pseudo-bucket labelled "IPSW") in Setup.
//   - Each OS volume's filesystem, scanned per-volume in ProcessVolume.
//
// All scan state is held in the per-DMG path maps below; Finalize replaces
// d.Files with the computed set diffs.
type filesJob struct {
	d *Diff

	// prev/next are per-DMG path lists (key = DMG label like "filesystem",
	// "SystemOS", or the literal "IPSW" pseudo-bucket).
	prev map[string][]string
	next map[string][]string

	// hydrated holds the per-bucket FileDiff loaded from a cache hit. A
	// non-nil pointer marks the hydrate path so Finalize publishes it directly
	// to j.d.Files and ignores any partial Setup state (the IPSW zip scan still
	// runs on a cache hit because Setup precedes the hydration decision); nil
	// means "not hydrated". A zero-content hit yields a non-nil *FileDiff with
	// empty maps so Finalize still takes the hydrate branch.
	hydrated *FileDiff
}

var _ CacheableTask = (*filesJob)(nil)

func newFilesJob(d *Diff) *filesJob {
	return &filesJob{
		d:    d,
		prev: make(map[string][]string),
		next: make(map[string][]string),
	}
}

func (j *filesJob) Name() string { return "files" }

// Needs reports true for every OS volume — files diff walks them all.
func (j *filesJob) Needs(typ string) bool {
	switch typ {
	case "fs", "sys", "app", "exc":
		return true
	}
	return false
}

// Setup scans the IPSW zip pseudo-bucket. This work needs no mounts and
// happens once before the volume loop.
func (j *filesJob) Setup(storage.Store) error {
	if err := search.ForEachFileInZip(j.d.Old.IPSWPath, "IPSW", "", j.collectOld); err != nil {
		return err
	}
	if err := search.ForEachFileInZip(j.d.New.IPSWPath, "IPSW", "", j.collectNew); err != nil {
		return err
	}
	return nil
}

// ProcessVolume walks both sides of the given volume and appends discovered
// file paths to the per-DMG buckets keyed by volumeLabel(typ). Scan state
// stays per-DMG; there is nothing to free until Finalize.
func (j *filesJob) ProcessVolume(typ, oldRoot, newRoot string) error {
	label := volumeLabel(typ)
	if oldRoot != "" {
		if err := search.ForEachFileInMount(oldRoot, label, "", j.collectOld); err != nil {
			return err
		}
	}
	if newRoot != "" {
		if err := search.ForEachFileInMount(newRoot, label, "", j.collectNew); err != nil {
			return err
		}
	}
	return nil
}

// Finalize computes the per-DMG set diffs and replaces d.Files. On the
// cache-hit path (j.hydrated non-nil) the orchestrator excluded the task from
// the volume walk, so there is no per-volume scan state to fold. Setup still
// ran (it precedes the hydration decision) and populated j.prev/j.next["IPSW"]
// from the zip scan, but that partial state MUST NOT leak into the published
// result: publish the hydrated FileDiff directly and discard the Setup buckets.
func (j *filesJob) Finalize() error {
	if j.hydrated != nil {
		j.d.Files = j.hydrated
		j.prev = nil
		j.next = nil
		return nil
	}

	j.d.Files = &FileDiff{
		New:     make(map[string][]string),
		Removed: make(map[string][]string),
	}
	for dmg := range j.prev {
		j.d.Files.New[dmg] = utils.Difference(j.next[dmg], j.prev[dmg])
		j.d.Files.Removed[dmg] = utils.Difference(j.prev[dmg], j.next[dmg])
		sort.Strings(j.d.Files.New[dmg])
		sort.Strings(j.d.Files.Removed[dmg])
	}
	// Catch DMGs that exist only on the new side.
	for dmg := range j.next {
		if _, seen := j.prev[dmg]; seen {
			continue
		}
		j.d.Files.New[dmg] = utils.Difference(j.next[dmg], nil)
		sort.Strings(j.d.Files.New[dmg])
	}
	return nil
}

func (j *filesJob) collectOld(dmg, path string) error {
	j.prev[dmg] = append(j.prev[dmg], path)
	return nil
}

func (j *filesJob) collectNew(dmg, path string) error {
	j.next[dmg] = append(j.next[dmg], path)
	return nil
}

// filesCacheVersion is the cache payload / output-semantics version for
// filesJob. Bump it whenever the persisted row layout (the per-bucket
// FileDiff), the scanned input set (the IPSW zip pseudo-bucket plus the four OS
// volumes), or the rendered Files section semantics change in a way that
// invalidates rows written by a prior ipsw build.
const filesCacheVersion = 1

// Version reports the cache payload / output-semantics version. See
// filesCacheVersion.
func (j *filesJob) Version() int { return filesCacheVersion }

// OptionsHash digests every output-affecting option for filesJob. The job has
// no output-affecting flags: it always scans the IPSW zip pseudo-bucket and
// every OS volume for the full file listing, computes the per-bucket set diff,
// and renders it through the fixed filesRenderer path. There are no allow/block
// lists, no verbosity, and no diff-tool selection. The tag also names the mount
// symlink policy because that changes the scanned file set without changing the
// IPSW volume digests.
func (j *filesJob) OptionsHash() string {
	return constOptionsHash("files-options-v-mount-root-symlinks", filesCacheVersion)
}

// InputHash digests the task-scope inputs. filesJob reads BOTH the four OS
// volumes AND the IPSW zip itself (the "IPSW" pseudo-bucket scanned in Setup),
// so the DMG digests alone are insufficient: a loose zip member added, removed,
// or changed at the zip root moves no DMG digest, and files is precisely the
// task that must detect that. The hash therefore folds the four-volume DMG
// fingerprint (via volumeDMGInputHashFor) together with the old and new IPSW
// zip central-directory digests (names + CRC32 + uncompressed size of every
// member). A zip-read failure on either side is folded as a stable error marker
// so two unreadable runs agree but a readable run differs.
func (j *filesJob) InputHash() string {
	h := sha256.New()
	_, _ = h.Write([]byte(volumeDMGInputHashFor(j.d.Old.Info, j.d.New.Info, ipswVolumeOrderMachos...)))
	_, _ = h.Write([]byte{0})
	writeZipListingDigest(h, "old", j.d.Old.IPSWPath)
	writeZipListingDigest(h, "new", j.d.New.IPSWPath)
	return hex.EncodeToString(h.Sum(nil))
}

// writeZipListingDigest folds one side's IPSW zip central-directory digest into
// h. An unreadable zip writes a stable error marker rather than failing the
// hash, so the InputHash stays a pure function of the inputs available.
func writeZipListingDigest(h io.Writer, side, ipswPath string) {
	_, _ = h.Write([]byte(side))
	_, _ = h.Write([]byte{0})
	digest, err := ipswZipListingDigest(ipswPath)
	if err != nil {
		_, _ = h.Write([]byte{0x00}) // error marker
		return
	}
	_, _ = h.Write([]byte{0x01})
	_, _ = h.Write(digest)
}

// filesCacheRowKey is the single row key for the cached per-bucket FileDiff.
const filesCacheRowKey = "files"

// Hydrate rebuilds the per-bucket FileDiff result from a cache hit. The single
// row holds a gob-encoded FileDiff. The decoded value is stashed in j.hydrated
// (a non-nil pointer) for Finalize to publish; the volume walk is skipped
// entirely by the orchestrator. A zero-row hit (the empty-result case, where
// persistTo wrote nothing) yields a non-nil *FileDiff with empty maps so
// Finalize still takes the hydrate branch and publishes the empty result.
func (j *filesJob) Hydrate(scope storage.Scope, store storage.Store) error {
	out := &FileDiff{
		New:     make(map[string][]string),
		Removed: make(map[string][]string),
	}
	err := store.Iter(scope, func(key string, decode func(v any) error) error {
		var diff FileDiff
		if err := decode(&diff); err != nil {
			return fmt.Errorf("files: hydrate %s: %w", key, err)
		}
		out = &diff
		return nil
	})
	if err != nil {
		return err
	}
	j.hydrated = out
	return nil
}

// persistTo writes the per-bucket FileDiff from the freshly-computed result. It
// runs only after a successful fresh walk + Finalize, so it reads from
// j.d.Files (the published result). An all-empty result writes zero rows
// (matching the empty-result contract: a later zero-row Hydrate yields a
// non-nil empty FileDiff), so a fully-cached rerun that finds no file changes
// still hydrates byte-identically to a fresh empty run.
func (j *filesJob) persistTo(scope storage.Scope, store storage.Store) error {
	if !fileDiffHasContent(j.d.Files) {
		return nil
	}
	if err := store.Put(scope, filesCacheRowKey, j.d.Files); err != nil {
		return fmt.Errorf("files: persist: %w", err)
	}
	return nil
}

// fileDiffHasContent reports whether a FileDiff carries any new or removed
// paths in a rendered bucket. It mirrors filesRenderer.Empty so persistTo's
// "write only when content-bearing" guard matches the render-time emptiness
// check exactly.
func fileDiffHasContent(diff *FileDiff) bool {
	if diff == nil {
		return false
	}
	for _, t := range filesRenderTypes {
		if len(diff.New[t]) > 0 || len(diff.Removed[t]) > 0 {
			return true
		}
	}
	return false
}

// filesRenderer owns the per-task Markdown/HTML/JSON emission for the
// `## Files` section. Render-time state is the per-bucket FileDiff
// produced by [filesJob.Finalize].
type filesRenderer struct {
	diff *FileDiff
}

func newFilesRenderer(diff *FileDiff) *filesRenderer {
	return &filesRenderer{diff: diff}
}

// JSONKey returns the stable JSON key that files payloads embed under in
// the top-level report DTO.
func (r *filesRenderer) JSONKey() string { return "files" }

// filesRenderTypes is the per-bucket render order used by the `## Files`
// section. It matches the order the inlined body in md.go iterated.
var filesRenderTypes = []string{"IPSW", "filesystem", "SystemOS", "AppOS", "ExclaveOS"}

// Empty reports whether the section has nothing to render. A FileDiff
// whose New/Removed maps only carry empty slices counts as empty.
func (r *filesRenderer) Empty() bool {
	if r.diff == nil {
		return true
	}
	for _, t := range filesRenderTypes {
		if len(r.diff.New[t]) > 0 || len(r.diff.Removed[t]) > 0 {
			return false
		}
	}
	return true
}

// Markdown emits the `## Files` section. The byte sequence must remain
// identical to the prior inlined body in md.go.
func (r *filesRenderer) Markdown(out *strings.Builder, outputDir string) error {
	if r.diff == nil {
		return nil
	}
	hasNewFiles := false
	hasRemovedFiles := false
	for _, t := range filesRenderTypes {
		if len(r.diff.New[t]) > 0 {
			hasNewFiles = true
		}
		if len(r.diff.Removed[t]) > 0 {
			hasRemovedFiles = true
		}
	}
	if hasNewFiles || hasRemovedFiles {
		out.WriteString("## Files\n\n")
	}
	if hasNewFiles {
		out.WriteString("### 🆕 New\n\n")
		for _, t := range filesRenderTypes {
			sec := listSection{headingPrefix: "####", title: t, tag: "NEW", subDir: "FILES", label: t, spillAt: filesSpillThreshold}
			if err := renderNameList(out, sec, r.diff.New[t], outputDir); err != nil {
				return err
			}
		}
	}
	if hasRemovedFiles {
		out.WriteString("### ❌ Removed\n\n")
		for _, t := range filesRenderTypes {
			sec := listSection{headingPrefix: "####", title: t, tag: "Removed", subDir: "FILES", label: t, spillAt: filesSpillThreshold}
			if err := renderNameList(out, sec, r.diff.Removed[t], outputDir); err != nil {
				return err
			}
		}
	}
	return nil
}

// filesHTMLTemplate renders the per-bucket Files body. It must produce
// bytes identical to the slice of diffHTMLPageTemplate it replaces.
const filesHTMLTemplate = `
{{- if .New }}
          <h3 id="files-new">New</h3>
          {{- range .New }}
          <div class="diff-entry">
            <h4>{{ .Name }} ({{ len .Items }})</h4>
            <ul>{{ range .Items }}<li><code>{{ . }}</code></li>{{ end }}</ul>
          </div>
          {{- end }}
{{- end }}
{{- if .Removed }}
          <h3 id="files-removed">Removed</h3>
          {{- range .Removed }}
          <div class="diff-entry">
            <h4>{{ .Name }} ({{ len .Items }})</h4>
            <ul>{{ range .Items }}<li><code>{{ . }}</code></li>{{ end }}</ul>
          </div>
          {{- end }}
{{- end }}`

// HTML returns the per-task HTML fragment for the `Files` section. The
// fragment Body excludes the section's <h2> heading.
func (r *filesRenderer) HTML() (HTMLFragment, error) {
	diff := convertFileDiff(r.diff)
	if diff == nil {
		return HTMLFragment{Heading: "Files"}, nil
	}
	body, err := executeHTMLTaskTemplate("files-html", filesHTMLTemplate, diff)
	if err != nil {
		return HTMLFragment{}, err
	}
	return HTMLFragment{Heading: "Files", Body: body}, nil
}

// JSON returns the per-task report payload: the per-bucket [FileDiff]
// embedded under [filesRenderer.JSONKey] in the top-level report DTO.
// Returns the underlying pointer as-is so buildReport's omitempty handling
// matches the legacy `Diff.Files` field encoding (a nil pointer drops the
// key entirely).
func (r *filesRenderer) JSON() any {
	return r.diff
}
