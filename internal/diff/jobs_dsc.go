package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
)

// dscJob diffs the dyld_shared_cache between old and new SystemOS cryptex
// roots. Modern IPSWs carry DSCs in the SystemOS cryptex; older pre-cryptex
// IPSWs carry them in the filesystem volume.
//
// Unlike the OS-volume jobs, dscJob produces THREE outputs from a single
// ProcessVolume call: the dylib MachoDiff (d.Dylibs) and the old/new WebKit
// version strings (d.Old.Webkit / d.New.Webkit). All three are cached and
// hydrated together so a warm rerun skips the "sys" (or pre-cryptex "fs")
// mount entirely.
type dscJob struct {
	d    *Diff
	conf *mcmd.DiffConfig

	// hydrated holds the three DSC outputs loaded from a cache hit. Non-nil
	// only on the hydrate path; Finalize publishes it to d.Dylibs /
	// d.Old.Webkit / d.New.Webkit and skips the volume walk. The orchestrator
	// excludes a hydrated task from the walk, so ProcessVolume never runs on a
	// hit. A zero-row hit yields a non-nil empty marker so Finalize still takes
	// the hydrate branch.
	hydrated *dscHydrated
}

// dscHydrated is the cached result shape for dscJob: the three outputs the
// DSC/WebKit/Dylibs report sections render from.
type dscHydrated struct {
	Dylibs    *mcmd.MachoDiff
	OldWebkit string
	NewWebkit string
}

var _ CacheableTask = (*dscJob)(nil)

func newDSCJob(d *Diff) *dscJob {
	j := &dscJob{d: d}
	// machoDiffConfig reads d.conf; guard the nil-d / nil-conf cases that the
	// Needs-only construction paths (and tests) exercise. OptionsHash is the
	// only consumer of j.conf, and a job without a config is never cached
	// (taskScope requires a derivable identity), so a nil conf there is inert.
	if d != nil && d.conf != nil {
		j.conf = d.dscDiffConfig()
	}
	return j
}

func (j *dscJob) Name() string { return "dsc" }

func (j *dscJob) Needs(typ string) bool {
	if j == nil || j.d == nil {
		return typ == "sys"
	}
	// The volume loop gates before mount.Session.Root("sys") can fall back to
	// the filesystem DMG, so request "fs" only when neither side has a distinct
	// SystemOS cryptex. For MIXED pairs (one side pre-cryptex, one with
	// Cryptex1,SystemOS) the job runs in the "sys" phase and the pre-cryptex
	// side's root arrives via the orchestrator's session fallback (see
	// WantsSessionFallback), resolving to that side's filesystem DMG.
	if volumeResolves(j.d.Old.Info, "sys") || volumeResolves(j.d.New.Info, "sys") {
		return typ == "sys"
	}
	return typ == "fs"
}

// WantsSessionFallback opts dscJob into the orchestrator's session-resolved
// fallback root for sides that lack a SystemOS cryptex during the "sys"
// phase. mount.Session.Root("sys") falls back to the filesystem DMG for
// pre-cryptex IPSWs — exactly where the DSC lives on those builds — so a
// mixed pre-cryptex-vs-cryptex pair diffs each side's real DSC location
// instead of failing on an empty root.
func (j *dscJob) WantsSessionFallback(typ string) bool { return typ == "sys" }

// ProcessVolume runs the DSC diff directly against the provided roots.
// All output (d.Old.Webkit, d.New.Webkit, d.Dylibs) is written in place
// during this call; nothing accumulates across volumes (single-volume job).
func (j *dscJob) ProcessVolume(typ, oldRoot, newRoot string) error {
	return j.d.diffDSCBetweenRoots(oldRoot, newRoot)
}

// Finalize publishes the hydrated DSC outputs on a cache hit. On the fresh-walk
// path ProcessVolume already populated d.Dylibs / d.Old.Webkit / d.New.Webkit
// in place, so Finalize is a no-op. On a cache hit the orchestrator excludes
// this job from the volume walk (ProcessVolume never runs), so Finalize is the
// only place the hydrated result is published.
func (j *dscJob) Finalize() error {
	if j.hydrated == nil {
		return nil
	}
	j.d.Dylibs = j.hydrated.Dylibs
	j.d.Old.Webkit = j.hydrated.OldWebkit
	j.d.New.Webkit = j.hydrated.NewWebkit
	return nil
}

// dscCacheVersion is the cache payload / output-semantics version for dscJob.
// Bump it whenever the persisted row layout (the three DSC outputs), the
// InputHash composition, or the rendered DSC/WebKit/Dylibs section semantics
// change in a way that invalidates rows written by a prior ipsw build. The
// feature is unreleased, so it starts at 1; bump only after a release ships.
const dscCacheVersion = 1

// Version reports the cache payload / output-semantics version. See
// dscCacheVersion.
func (j *dscJob) Version() int { return dscCacheVersion }

// OptionsHash digests every output-affecting option for the DSC diff.
// diffDSCBetweenRoots builds its mcmd.DiffConfig from the same source knobs as
// machosJob, but DSC image diffs suppress load-command comparison because cache
// image load-command bytes are too noisy for the report. j.conf mirrors that
// config, so OptionsHash folds those fields via the shared hashMachoDiffConfig
// helper:
//
//   - AllowList (sorted)
//   - BlockList (sorted)
//   - Markdown
//   - Color
//   - DiffTool
//   - CStrings
//   - FuncStarts
//   - IgnoreLoadCommands (true for DSC)
//   - PemDB (empty for DSC; folded for parity with machos)
//   - SymMap (empty for DSC; folded for parity with machos)
//   - Verbose
//
// The "dsc-options-v" tag keeps the digest distinct from machos even when the
// folded config is byte-identical, so the two tasks never share a cache scope.
func (j *dscJob) OptionsHash() string {
	h := sha256.New()
	_, _ = h.Write([]byte("dsc-options-v"))
	_, _ = h.Write([]byte{byte(dscCacheVersion)})
	hashMachoDiffConfig(h, j.conf)
	return hex.EncodeToString(h.Sum(nil))
}

// InputHash digests the task-scope inputs PER SIDE: each side folds the
// BuildManifest digest of the volume its DSC actually lives on — the SystemOS
// cryptex when that side carries one, else that side's pre-cryptex filesystem
// volume. Per-side resolution matters for MIXED pairs (old pre-cryptex, new
// cryptex): the old side's input is its fs DMG, not the absent sys cryptex,
// and the session fallback mounts exactly that volume for the diff. Uses
// ipswVolumeManifestDigest, the same per-volume digest source the
// unchanged-volume short-circuit uses, so the cache identity tracks the
// artifact bytes the diff actually reads on each side.
func (j *dscJob) InputHash() string {
	h := sha256.New()
	oldTyp := dscVolumeFor(j.d.Old.Info)
	newTyp := dscVolumeFor(j.d.New.Info)
	_, _ = h.Write([]byte(oldTyp))
	_, _ = h.Write([]byte{0})
	writeVolumeDigest(h, "old", j.d.Old.Info, oldTyp)
	_, _ = h.Write([]byte(newTyp))
	_, _ = h.Write([]byte{0})
	writeVolumeDigest(h, "new", j.d.New.Info, newTyp)
	return hex.EncodeToString(h.Sum(nil))
}

// dscVolumeFor returns the volume holding one side's DSC: the SystemOS
// cryptex when the side has one, else the pre-cryptex filesystem volume.
func dscVolumeFor(inf *info.Info) string {
	if volumeResolves(inf, "sys") {
		return "sys"
	}
	return "fs"
}

// dscCacheRowKey identifies each of the three DSC outputs in the cache.
const (
	dscRowDylibs    = "dylibs"
	dscRowWebkitOld = "webkit-old"
	dscRowWebkitNew = "webkit-new"
)

// Hydrate rebuilds the three DSC outputs from a cache hit. The dylib MachoDiff
// is a gob-encoded *mcmd.MachoDiff under "dylibs"; each WebKit version is a
// gob-encoded string under "webkit-old" / "webkit-new". A zero-row hit (every
// output empty, so persistTo wrote nothing) yields a non-nil empty marker so
// Finalize still takes the hydrate branch and publishes the empty result.
//
// Dylibs defaults to a non-nil empty *mcmd.MachoDiff (matching dcmd.Diff, which
// always returns a non-nil value even with zero changes) so the published
// d.Dylibs is byte-identical to a fresh empty run: buildReport emits "dylibs":{}
// whenever d.Dylibs != nil, and a nil here would drop the key.
func (j *dscJob) Hydrate(scope storage.Scope, store storage.Store) error {
	out := &dscHydrated{Dylibs: &mcmd.MachoDiff{Updated: make(map[string]string)}}
	err := store.Iter(scope, func(key string, decode func(v any) error) error {
		switch key {
		case dscRowDylibs:
			var diff mcmd.MachoDiff
			if err := decode(&diff); err != nil {
				return fmt.Errorf("dsc: hydrate %s: %w", key, err)
			}
			out.Dylibs = &diff
		case dscRowWebkitOld:
			if err := decode(&out.OldWebkit); err != nil {
				return fmt.Errorf("dsc: hydrate %s: %w", key, err)
			}
		case dscRowWebkitNew:
			if err := decode(&out.NewWebkit); err != nil {
				return fmt.Errorf("dsc: hydrate %s: %w", key, err)
			}
		default:
			return fmt.Errorf("dsc: hydrate unknown row %q", key)
		}
		return nil
	})
	if err != nil {
		return err
	}
	j.hydrated = out
	return nil
}

// persistTo writes one row per content-bearing DSC output from the freshly
// computed result (d.Dylibs / d.Old.Webkit / d.New.Webkit). Empty outputs write
// no row (the empty-result contract): an empty Dylibs writes no "dylibs" row, an
// empty WebKit string writes no "webkit-*" row. Each output is handled
// independently, so a non-empty Dylibs with empty WebKit (or vice versa) round-
// trips correctly.
func (j *dscJob) persistTo(scope storage.Scope, store storage.Store) error {
	if machoDiffHasContent(j.d.Dylibs) {
		if err := store.Put(scope, dscRowDylibs, j.d.Dylibs); err != nil {
			return fmt.Errorf("dsc: persist dylibs: %w", err)
		}
	}
	if j.d.Old.Webkit != "" {
		if err := store.Put(scope, dscRowWebkitOld, j.d.Old.Webkit); err != nil {
			return fmt.Errorf("dsc: persist webkit-old: %w", err)
		}
	}
	if j.d.New.Webkit != "" {
		if err := store.Put(scope, dscRowWebkitNew, j.d.New.Webkit); err != nil {
			return fmt.Errorf("dsc: persist webkit-new: %w", err)
		}
	}
	return nil
}
