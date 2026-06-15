package diff

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	iofs "io/fs"
	"path/filepath"
	"strings"
	"time"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/kernelcache"
)

// kextsTask owns the kernelcache parse plus the per-renderer emission for
// the `### Kexts` sub-section. Parse wraps the existing
// [Diff.parseKernelcache] so the kernel symbolicate/diff pipeline is
// unchanged; the render-time state is the [mcmd.MachoDiff] produced on
// [Diff.Kexts] by that parse.
type kextsTask struct {
	d *Diff

	// hydrated holds the cached kernelcache result loaded from a cache hit.
	// Non-nil only on the hydrate path; Hydrate publishes it directly to the
	// Diff (d.Kexts plus the rendered Kernel version fields) and the
	// orchestrator skips Parse. A zero-content hit still yields a non-nil
	// payload so the hydrate branch is taken.
	hydrated *kextsCachePayload
}

func newKextsTask(d *Diff) *kextsTask {
	return &kextsTask{d: d}
}

// Name returns the stable identifier used for logs and cache scoping.
func (t *kextsTask) Name() string { return "kexts" }

// JSONKey returns the stable public JSON key under which the task's
// payload embeds in the top-level report DTO.
func (t *kextsTask) JSONKey() string { return "kexts" }

// Empty reports whether the task has nothing to render and the
// orchestrator should skip the section.
func (t *kextsTask) Empty() bool {
	return t.d.Kexts == nil ||
		(len(t.d.Kexts.New) == 0 && len(t.d.Kexts.Removed) == 0 && len(t.d.Kexts.Updated) == 0)
}

// Parse runs the kernelcache extraction and diff. Wraps the existing
// [Diff.parseKernelcache] so behavior (sameKernel short-circuit,
// signature symbolication, MachO diff) is preserved. Skipped by the
// orchestrator on a cache hit (Hydrate publishes the result).
func (t *kextsTask) Parse(_ context.Context, d *Diff) error {
	return d.parseKernelcache()
}

// kextsCacheVersion is the cache payload / output-semantics version for
// kextsTask. The diff cache shipped in v3.1.693, so bump this whenever the
// persisted payload layout (the kext MachoDiff plus the rendered Kernel version
// fields, their display date zones, and the sameKernel short-circuit), the
// kernelcache parse/diff pipeline, the OptionsHash composition, or the rendered
// Kexts/Kernel section semantics change in a way that invalidates rows written
// by a prior ipsw build.
const kextsCacheVersion = 1

// Version reports the cache payload / output-semantics version. See
// kextsCacheVersion.
func (t *kextsTask) Version() int { return kextsCacheVersion }

// OptionsHash digests every output-affecting option for the kernelcache diff.
// parseKernelcache builds a mcmd.DiffConfig inline from d.conf
// (AllowList/BlockList/CStrings/FuncStarts/Verbose) with the same fixed cosmetic
// fields machosJob renders with (Markdown=true, Color=false, DiffTool="git"),
// plus the SymMap derived from d.conf.Signatures. The hash folds the same
// DiffConfig fields machosJob folds (via hashMachoDiffConfig) — built to mirror
// the kcmd.Diff config — and additionally folds d.conf.Signatures: the PATH so
// pointing at a different signatures set moves the hash, and the directory
// CONTENT identity (per-file rel-path + size + mtime via signaturesDirIdentity)
// so regenerating the signature files in place at the same path also moves it.
// Without the content fold, a re-run after `git pull` in the symbolicator repo
// would hydrate the old symbolicated kext diff and serve stale names.
func (t *kextsTask) OptionsHash() string {
	h := sha256.New()
	hashMachoDiffConfig(h, t.kextDiffConfig())
	_, _ = h.Write([]byte("Signatures"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(t.d.conf.Signatures))
	_, _ = h.Write([]byte{0})
	if id, ok := signaturesDirIdentity(t.d.conf.Signatures); ok {
		_, _ = h.Write([]byte{0x01}) // present marker
		_, _ = h.Write(id)
	} else {
		_, _ = h.Write([]byte{0x00}) // absent marker (no --signatures, or unreadable)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// signaturesDirIdentity returns a cheap content identity for the signatures
// directory: every regular file's slash-relative path, size, and mtime,
// folded in WalkDir's deterministic lexical order. It is a package var so
// tests can substitute a fake without writing real signature trees. ok is
// false for an empty path, an unreadable tree, or a tree with no files.
//
// The identity is deliberately cheap (stat, not content hashing): signature
// sets contain hundreds of JSON files and are re-resolved on every run that
// misses. Limitation (same as kdkFileIdentity): a file replaced in place with
// identical size and mtime is treated as unchanged.
var signaturesDirIdentity = func(dir string) (digest []byte, ok bool) {
	if dir == "" {
		return nil, false
	}
	h := sha256.New()
	found := false
	if err := filepath.WalkDir(dir, func(path string, d iofs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		found = true
		_, _ = h.Write([]byte(filepath.ToSlash(rel)))
		_, _ = h.Write([]byte{0})
		var b [16]byte
		binary.BigEndian.PutUint64(b[:8], uint64(fi.Size()))
		binary.BigEndian.PutUint64(b[8:], uint64(fi.ModTime().UnixNano()))
		_, _ = h.Write(b[:])
		return nil
	}); err != nil {
		return nil, false
	}
	if !found {
		return nil, false
	}
	return h.Sum(nil), true
}

// kextDiffConfig mirrors the output-affecting fields of the mcmd.DiffConfig
// parseKernelcache passes to kcmd.Diff. SymMap is omitted: it is derived from
// d.conf.Signatures, which OptionsHash folds separately, and is unset on the
// kernelcaches the hash never opens.
func (t *kextsTask) kextDiffConfig() *mcmd.DiffConfig {
	return &mcmd.DiffConfig{
		Markdown:   true,
		Color:      false,
		DiffTool:   "git",
		AllowList:  t.d.conf.AllowList,
		BlockList:  t.d.conf.BlockList,
		CStrings:   t.d.conf.CStrings,
		FuncStarts: t.d.conf.FuncStarts,
		Verbose:    t.d.conf.Verbose,
	}
}

// InputHash digests the task-scope inputs: the old and new BuildManifest
// KernelCache digests, folded over sorted models, old then new. It reuses the
// exact digest source ipswKernelcacheManifestDigestsEqual uses for the
// sameKernel short-circuit, so the cache identity tracks the same kernelcache
// artifact bytes the orchestrator inspects to skip the diff.
func (t *kextsTask) InputHash() string {
	return kernelcacheDMGInputHash(t.d.Old.Info, t.d.New.Info)
}

// kextsCachePayload is the single cached row for kextsTask. It carries the kext
// MachoDiff and both rendered Kernel version structs so a hydrate restores
// every piece of state parseKernelcache feeds into rendering (the `### Kexts`
// sub-section AND the `## Kernel` version table). Diff is nil when the kernel
// is functionally unchanged (the sameKernel short-circuit produces no diff).
type kextsCachePayload struct {
	Diff            *mcmd.MachoDiff
	OldVersion      *kernelcache.Version
	NewVersion      *kernelcache.Version
	OldDateZoneName string
	OldDateZoneOff  int
	NewDateZoneName string
	NewDateZoneOff  int
	SameKernel      bool
}

// kextsCacheRowKey is the single row key for the cached kernelcache result.
const kextsCacheRowKey = "kexts"

// Hydrate rebuilds the kernelcache result from a cache hit. The single row holds
// a gob-encoded kextsCachePayload; the decoded value is stashed in t.hydrated
// and published to the Diff immediately so rendering (which reads d.Kexts and
// d.Old/New.Kernel.Version) sees the cached state without re-parsing. A
// zero-row hit (the empty-result case) yields a non-nil empty payload so the
// hydrate branch is still taken.
func (t *kextsTask) Hydrate(scope storage.Scope, store storage.Store) error {
	out := &kextsCachePayload{}
	err := store.Iter(scope, func(key string, decode func(v any) error) error {
		var payload kextsCachePayload
		if err := decode(&payload); err != nil {
			return fmt.Errorf("kexts: hydrate %s: %w", key, err)
		}
		out = &payload
		return nil
	})
	if err != nil {
		return err
	}
	t.hydrated = out
	restoreKernelVersionDateZone(out.OldVersion, out.OldDateZoneName, out.OldDateZoneOff)
	restoreKernelVersionDateZone(out.NewVersion, out.NewDateZoneName, out.NewDateZoneOff)
	t.d.Kexts = out.Diff
	t.d.Old.Kernel.Version = out.OldVersion
	t.d.New.Kernel.Version = out.NewVersion
	t.d.sameKernel = out.SameKernel
	return nil
}

// persistTo writes the kernelcache result from the freshly-parsed Diff. It runs
// only after a successful Parse. An empty result (no kext diff and no kernel
// version fields, i.e. the sameKernel short-circuit fired) writes zero rows so a
// later zero-row Hydrate yields a non-nil empty payload and publishes the same
// nil d.Kexts / nil Kernel.Version a fresh short-circuited run produces.
func (t *kextsTask) persistTo(scope storage.Scope, store storage.Store) error {
	oldZoneName, oldZoneOff := kernelVersionDateZone(t.d.Old.Kernel.Version)
	newZoneName, newZoneOff := kernelVersionDateZone(t.d.New.Kernel.Version)
	payload := kextsCachePayload{
		Diff:            t.d.Kexts,
		OldVersion:      t.d.Old.Kernel.Version,
		NewVersion:      t.d.New.Kernel.Version,
		OldDateZoneName: oldZoneName,
		OldDateZoneOff:  oldZoneOff,
		NewDateZoneName: newZoneName,
		NewDateZoneOff:  newZoneOff,
		SameKernel:      t.d.sameKernel,
	}
	if !kextsPayloadHasContent(&payload) {
		return nil
	}
	if err := store.Put(scope, kextsCacheRowKey, payload); err != nil {
		return fmt.Errorf("kexts: persist: %w", err)
	}
	return nil
}

// kextsPayloadHasContent reports whether a payload carries any output-bearing
// state: a non-empty kext MachoDiff or either rendered Kernel version. It
// mirrors the render-time emptiness checks (kextsTask.Empty for the kext diff;
// the `## Kernel` section gates on both versions being non-nil) so persistTo's
// "write only when content-bearing" guard matches what gets rendered.
func kextsPayloadHasContent(p *kextsCachePayload) bool {
	if p == nil {
		return false
	}
	if p.OldVersion != nil || p.NewVersion != nil {
		return true
	}
	d := p.Diff
	return d != nil && (len(d.New) > 0 || len(d.Removed) > 0 || len(d.Updated) > 0)
}

func kernelVersionDateZone(v *kernelcache.Version) (string, int) {
	if v == nil {
		return "", 0
	}
	return v.KernelVersion.Date.Zone()
}

func restoreKernelVersionDateZone(v *kernelcache.Version, name string, offset int) {
	if v == nil || name == "" {
		return
	}
	date := v.KernelVersion.Date
	v.KernelVersion.Date = time.Date(
		date.Year(), date.Month(), date.Day(),
		date.Hour(), date.Minute(), date.Second(), date.Nanosecond(),
		time.FixedZone(name, offset),
	)
}

// Markdown emits the kexts sub-section. The byte sequence must remain
// identical to the prior inlined body in md.go.
func (t *kextsTask) Markdown(w *strings.Builder, outputDir string) error {
	if t.Empty() {
		return nil
	}
	w.WriteString("### Kexts\n\n")
	return renderMachoDiff(w, listSection{headingPrefix: "####", subDir: "KEXTS", label: "Kexts"}, t.d.Kexts, outputDir)
}

// kextsHTMLTemplate renders the kexts HTML body the outer page template
// previously emitted between
//
//	{{- if .Kexts }}
//
// and
//
//	{{- end }}
//
// for the kexts block. The body keeps the leading `\n          ` so the
// outer template can splice the fragment via
// `{{- if not .KextsFragment.Empty }}{{ .KextsFragment.Body }}{{- end }}`
// and produce byte-identical output.
const kextsHTMLTemplate = `
          <h3 id="kexts">Kexts</h3>
          {{- template "machoDiffSection" dict "Prefix" "kexts" "Diff" . }}`

// HTML returns the per-task HTML fragment Body for the `Kexts`
// sub-section. The outer template splices the body in at the same DOM
// position the inlined template emitted previously.
func (t *kextsTask) HTML() (HTMLFragment, error) {
	if t.Empty() {
		return HTMLFragment{Heading: "Kexts"}, nil
	}
	body, err := executeHTMLTaskTemplate("kexts-html", kextsHTMLTemplate, convertMachoDiff(t.d.Kexts))
	if err != nil {
		return HTMLFragment{}, err
	}
	return HTMLFragment{Heading: "Kexts", Body: body}, nil
}

// JSON returns the per-task report payload: the [mcmd.MachoDiff] embedded
// under [kextsTask.JSONKey] in the top-level report DTO. Returns the
// underlying pointer as-is so buildReport's omitempty handling matches the
// legacy `Diff.Kexts` field encoding.
func (t *kextsTask) JSON() any {
	return t.d.Kexts
}

// Compile-time assertions: kextsTask satisfies the top-level task lifecycle and
// the cache contract. Its render surface (JSONKey / Empty / Markdown / HTML /
// JSON) is exercised through buildReport, the Markdown loop in md.go, and
// renderHTML, mirroring the *strings.Builder Markdown signature the per-section
// renderers use.
var (
	_ TopLevelTask  = (*kextsTask)(nil)
	_ CacheableTask = (*kextsTask)(nil)
)
