package diff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/storage"
)

// firmwaresTask owns the firmware diff parse plus the per-renderer
// emission for the `## Firmware` section. Parse wraps the existing
// [Diff.parseFirmwares] so the firmware enumeration pipeline is unchanged.
type firmwaresTask struct {
	d *Diff

	// hydrated holds the MachoDiff loaded from a cache hit. Non-nil only on the
	// hydrate path; Hydrate publishes it directly to d.Firmwares and the
	// orchestrator skips Parse. A zero-row hit yields a non-nil empty MachoDiff
	// so the hydrate branch is still taken and publishes byte-identical empty
	// output.
	hydrated *mcmd.MachoDiff
}

func newFirmwaresTask(d *Diff) *firmwaresTask {
	return &firmwaresTask{d: d}
}

// Name returns the stable identifier used for logs and cache scoping.
func (t *firmwaresTask) Name() string { return "firmwares" }

// JSONKey returns the stable public JSON key under which the task's
// payload embeds in the top-level report DTO.
func (t *firmwaresTask) JSONKey() string { return "firmwares" }

// Empty reports whether the task has nothing to render.
func (t *firmwaresTask) Empty() bool {
	return t.d.Firmwares == nil ||
		(len(t.d.Firmwares.New) == 0 &&
			len(t.d.Firmwares.Removed) == 0 &&
			len(t.d.Firmwares.Updated) == 0)
}

// Parse runs the firmware enumeration. Wraps the existing
// [Diff.parseFirmwares] so per-mode behavior (OTA / Directory / IPSW) is
// unchanged.
func (t *firmwaresTask) Parse(_ context.Context, d *Diff) error {
	return d.parseFirmwares()
}

// firmwaresCacheVersion is the cache payload / output-semantics version for
// firmwaresTask. The diff cache shipped in v3.1.693, so bump this whenever the
// persisted row layout (the firmware MachoDiff), the firmware enumeration/diff
// pipeline, or the rendered `## Firmware` section semantics change in a way that
// invalidates rows written by a prior ipsw build.
const firmwaresCacheVersion = 1

// Version reports the cache payload / output-semantics version. See
// firmwaresCacheVersion.
func (t *firmwaresTask) Version() int { return firmwaresCacheVersion }

// OptionsHash digests every output-affecting option for the firmware diff.
// parseFirmwares builds a mcmd.DiffConfig from d.conf
// (AllowList/BlockList/CStrings/FuncStarts/Verbose) with the same fixed cosmetic
// fields machosJob renders with (Markdown=true, Color=false, DiffTool="git").
// The hash folds the same DiffConfig fields machosJob folds (via
// hashMachoDiffConfig) — built to mirror the DiffFirmwares config — so a rerun
// with different allow/block lists or strings/starts options cannot serve a stale
// rendered result. The explicit marker keeps pre-fix rows from being reused after
// firmware Mach-O keys became source-qualified by their containing IPSW/OTA IM4P
// member path.
func (t *firmwaresTask) OptionsHash() string {
	h := sha256.New()
	_, _ = h.Write([]byte("firmware-source-member-path-qualified-keys"))
	_, _ = h.Write([]byte{0})
	hashMachoDiffConfig(h, t.firmwareDiffConfig())
	return hex.EncodeToString(h.Sum(nil))
}

// firmwareDiffConfig mirrors the output-affecting fields of the mcmd.DiffConfig
// parseFirmwares passes to DiffFirmwares.
func (t *firmwaresTask) firmwareDiffConfig() *mcmd.DiffConfig {
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

// InputHash digests the task-scope inputs: the old and new IPSW zip
// central-directory digests filtered to ".im4p" members. parseFirmwares →
// DiffFirmwares → search.ForEachIm4pInIPSW reads the firmware artifacts straight
// from the IPSW zip's ".im4p" members (NOT from any BuildManifest DMG entry), so
// folding those members' names + CRC32 + uncompressed size tracks every firmware
// change. The IpswOld/IpswNew scope identity (full BuildManifest) is a backstop
// for the surrounding IPSW pair; the firmware content itself is covered here. A
// zip-read failure on either side is folded as a stable error marker so two
// unreadable runs agree but a readable run differs.
func (t *firmwaresTask) InputHash() string {
	h := sha256.New()
	writeFirmwareZipDigest(h, "old", t.d.Old.IPSWPath)
	writeFirmwareZipDigest(h, "new", t.d.New.IPSWPath)
	return hex.EncodeToString(h.Sum(nil))
}

// writeFirmwareZipDigest folds one side's ".im4p"-filtered IPSW zip
// central-directory digest into h. An unreadable zip writes a stable error
// marker rather than failing the hash, so the InputHash stays a pure function of
// the inputs available.
func writeFirmwareZipDigest(h io.Writer, side, ipswPath string) {
	_, _ = h.Write([]byte(side))
	_, _ = h.Write([]byte{0})
	digest, err := ipswFirmwareZipListingDigest(ipswPath)
	if err != nil {
		_, _ = h.Write([]byte{0x00}) // error marker
		return
	}
	_, _ = h.Write([]byte{0x01})
	_, _ = h.Write(digest)
}

// firmwaresCacheRowKey is the single row key for the cached firmware MachoDiff.
const firmwaresCacheRowKey = "firmwares"

// Hydrate rebuilds the firmware MachoDiff from a cache hit. The single row holds
// a gob-encoded *mcmd.MachoDiff; the decoded value is stashed in t.hydrated and
// published to d.Firmwares so rendering sees the cached state without re-parsing.
// A zero-row hit (the empty-result case) yields a non-nil empty MachoDiff so the
// hydrate branch is still taken and renders byte-identically to a fresh empty run.
func (t *firmwaresTask) Hydrate(scope storage.Scope, store storage.Store) error {
	out := &mcmd.MachoDiff{Updated: make(map[string]string)}
	err := store.Iter(scope, func(key string, decode func(v any) error) error {
		var diff mcmd.MachoDiff
		if err := decode(&diff); err != nil {
			return fmt.Errorf("firmwares: hydrate %s: %w", key, err)
		}
		out = &diff
		return nil
	})
	if err != nil {
		return err
	}
	t.hydrated = out
	t.d.Firmwares = out
	return nil
}

// persistTo writes the firmware MachoDiff from the freshly-parsed Diff. It runs
// only after a successful Parse. An empty result (no new/removed/updated firmware)
// writes zero rows so a later zero-row Hydrate yields a non-nil empty MachoDiff
// and renders byte-identically to a fresh empty run.
func (t *firmwaresTask) persistTo(scope storage.Scope, store storage.Store) error {
	if t.Empty() {
		return nil
	}
	if err := store.Put(scope, firmwaresCacheRowKey, t.d.Firmwares); err != nil {
		return fmt.Errorf("firmwares: persist: %w", err)
	}
	return nil
}

// Markdown emits the firmwares section. The byte sequence must remain
// identical to the prior inlined body in md.go.
func (t *firmwaresTask) Markdown(w *strings.Builder, outputDir string) error {
	if t.Empty() {
		return nil
	}
	w.WriteString("## Firmware\n\n")
	return renderMachoDiff(w, listSection{headingPrefix: "###", subDir: "FIRMWARE", label: "Firmware"}, t.d.Firmwares, outputDir)
}

// firmwaresHTMLTemplate renders the firmwares HTML body the outer page
// template previously emitted between
//
//	{{- if .Firmwares }}
//
// and
//
//	{{- end }}
//
// The leading "\n          " ensures the outer
// `{{- if not .FirmwaresFragment.Empty }}{{ .FirmwaresFragment.Body }}{{- end }}`
// splice produces byte-identical output.
const firmwaresHTMLTemplate = `
          <h2 id="firmwares">Firmwares</h2>
          {{- template "machoDiffSection" dict "Prefix" "fw" "Diff" . }}`

// HTML returns the per-task HTML fragment Body for the `Firmwares`
// section.
func (t *firmwaresTask) HTML() (HTMLFragment, error) {
	if t.Empty() {
		return HTMLFragment{Heading: "Firmwares"}, nil
	}
	body, err := executeHTMLTaskTemplate("firmwares-html", firmwaresHTMLTemplate, convertMachoDiff(t.d.Firmwares))
	if err != nil {
		return HTMLFragment{}, err
	}
	return HTMLFragment{Heading: "Firmwares", Body: body}, nil
}

// JSON returns the per-task report payload: the [mcmd.MachoDiff] embedded
// under [firmwaresTask.JSONKey] in the top-level report DTO.
func (t *firmwaresTask) JSON() any {
	return t.d.Firmwares
}

// Compile-time assertions: firmwaresTask satisfies the top-level task lifecycle
// and the cache contract; its render surface mirrors the per-section renderers.
var (
	_ TopLevelTask  = (*firmwaresTask)(nil)
	_ CacheableTask = (*firmwaresTask)(nil)
)
