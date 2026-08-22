/*
Copyright © 2018-2026 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package ota

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/ota"
)

// dscSchemaVersion is the version of the JSON report contract written by
// writeDSCReport. Bump for ANY key removal or semantic change; purely
// additive `phase` values do not require a bump.
const dscSchemaVersion = 1

// Stable source identifiers for the two non-cryptex sources. Cryptex-sourced
// files use the OTA member basename verbatim, which pkg/ota's reOTADscCryptex
// constrains to exactly six values.
const (
	sourceOTAAsset  = "ota-asset"
	sourcePayloadV2 = "payloadv2"
)

var errNoDSCMaterialized = errors.New(
	"no dyld_shared_cache files were materialized from any OTA source (cryptexes, asset files, payloadv2)")

var reDSCUber = regexp.MustCompile(dyld.CacheUberRegex)

// dscReport is the versioned machine-readable result of one --dyld extraction.
// Files and Errors are never nil, so they marshal as [] and never as null.
type dscReport struct {
	SchemaVersion int             `json:"schema_version"`
	Complete      bool            `json:"complete"`
	Files         []dscFileEntry  `json:"files"`
	Errors        []dscErrorEntry `json:"errors"`
}

// dscFileEntry is one successfully materialized file. Every key is always
// present so a consumer's decode is total.
type dscFileEntry struct {
	Path   string `json:"path"`   // slash separated, relative to the output root
	Arch   string `json:"arch"`   // "" when the filename carries no architecture
	Source string `json:"source"` // cryptex basename, "ota-asset", or "payloadv2"
}

// dscErrorEntry is one structured failure. Phase is a stable enum; Message is
// free-form diagnostic text that callers must not pattern-match on.
type dscErrorEntry struct {
	Phase   ota.Phase `json:"phase"`
	Source  string    `json:"source"` // "" when not attributable to one member
	Message string    `json:"message"`

	err error // not serialized; drives the human-mode exit-code policy
}

// dscSource is the OTA behavior extractDSC depends on. *ota.AA is adapted to
// it by otaDSCSource so extractDSC is unit-testable without firmware:
// *ota.File has only unexported fields and cannot be built outside pkg/ota.
type dscSource interface {
	ExtractFromCryptexesWithSourcesForArches(pattern, output string, arches []string) ([]ota.ExtractedFile, error)
	GetPayloadFilesWithCallback(pattern, payloadRange, output string, onFile func(dst string)) error
	AssetNames() []string   // non-dir OTA archive member names
	PostBOMNames() []string // non-dir post.bom entry names
	CopyAsset(name, outputPath string) error
}

type dscOptions struct {
	Output       string
	ReportRoot   string // base for report-relative paths
	PayloadRange string
	Arches       []string
	Prompt       func(question string) bool // nil means non-interactive consent

	pattern *regexp.Regexp
}

// extractDSC materializes every dyld_shared_cache ipsw can find in an OTA and
// returns a report of exactly what landed on disk and what failed.
//
// Sources run in order (cryptexes, direct OTA assets, payloadv2) and stop as
// soon as one is satisfied. It never prompts unless opts.Prompt is non-nil,
// and never writes to stdout.
func extractDSC(src dscSource, opts dscOptions) *dscReport {
	opts.pattern = dscPatternForArches(opts.Arches)
	rep := newDSCReport()
	dscFromCryptexes(src, opts, rep)
	if !rep.satisfied(opts.Arches) {
		dscFromAssets(src, opts, rep)
	}
	if !rep.satisfied(opts.Arches) {
		dscFromPayloads(src, opts, rep)
	}
	if missing := rep.missingArches(opts.Arches); len(missing) > 0 {
		rep.addErrors(ota.PhaseDSCDiscovery, "", fmt.Errorf(
			"no dyld_shared_cache files were materialized for requested architecture(s): %s",
			strings.Join(missing, ", ")))
	} else if len(rep.Files) == 0 {
		rep.addErrors(ota.PhaseDSCDiscovery, "", errNoDSCMaterialized)
	}
	return rep.finish()
}

func newDSCReport() *dscReport {
	return &dscReport{
		SchemaVersion: dscSchemaVersion,
		Files:         []dscFileEntry{},
		Errors:        []dscErrorEntry{},
	}
}

func failedDSCReport(phase ota.Phase, err error) *dscReport {
	rep := newDSCReport()
	rep.addErrors(phase, "", err)
	return rep.finish()
}

// addFile records a materialized file. A source that fails part way through
// falls through to the next one, which can re-materialize a path an earlier
// source already wrote; the later write owns the bytes on disk, so it replaces
// the earlier entry instead of appending a duplicate.
func (r *dscReport) addFile(root, dst, source string) {
	entry := dscFileEntry{
		Path:   dscReportPath(root, dst),
		Arch:   dscArch(dst),
		Source: source,
	}
	if i := slices.IndexFunc(r.Files, func(f dscFileEntry) bool { return f.Path == entry.Path }); i >= 0 {
		r.Files[i] = entry
		return
	}
	r.Files = append(r.Files, entry)
}

func (r *dscReport) addErrors(defaultPhase ota.Phase, source string, err error) {
	for _, e := range flattenErrors(err) {
		entry := dscErrorEntry{Phase: defaultPhase, Source: source, Message: e.Error(), err: e}
		if pe, ok := errors.AsType[*ota.PhaseError](e); ok {
			entry.Phase = pe.Phase
			if pe.Source != "" {
				entry.Source = pe.Source
			}
		}
		r.Errors = append(r.Errors, entry)
	}
}

func (r *dscReport) finish() *dscReport {
	r.Complete = len(r.Errors) == 0
	return r
}

// satisfied reports whether the sources run so far produced everything they
// were going to, so no later source needs to run. Cleanup failures are ignored
// because they happen after the copy already succeeded: nothing is missing, so
// re-running the (very expensive) payloadv2 scan would recover nothing.
func (r *dscReport) satisfied(arches []string) bool {
	if len(r.Files) == 0 || len(r.missingArches(arches)) > 0 {
		return false
	}
	for _, e := range r.Errors {
		if e.Phase != ota.PhaseCleanup {
			return false
		}
	}
	return true
}

// missingArches reports the requested architectures with no primary cache in
// the report. Sidecars (.symbols, .map, subcaches) do not count: they are
// useless without the primary cache, so an architecture they belong to still
// needs a later source to materialize it.
func (r *dscReport) missingArches(requested []string) []string {
	var missing []string
	for _, arch := range requested {
		if slices.Contains(missing, arch) {
			continue
		}
		if !slices.ContainsFunc(r.Files, func(f dscFileEntry) bool {
			a, primary := ota.DSCFileArch(f.Path)
			return primary && a == arch
		}) {
			missing = append(missing, arch)
		}
	}
	return missing
}

// fatalErr joins every recorded error except errNoDSCMaterialized so that in
// human mode "searched everywhere, found nothing" stays a zero exit.
func (r *dscReport) fatalErr() error {
	var errs []error
	for _, e := range r.Errors {
		if errors.Is(e.err, errNoDSCMaterialized) {
			continue
		}
		errs = append(errs, e.err)
	}
	return errors.Join(errs...)
}

func dscFromCryptexes(src dscSource, opts dscOptions, rep *dscReport) {
	log.Info("Searching OTA cryptexes for dyld_shared_cache files")
	out, err := src.ExtractFromCryptexesWithSourcesForArches(opts.pattern.String(), opts.Output, opts.Arches)
	for _, f := range out {
		rep.addFile(opts.ReportRoot, f.Path, f.Source)
	}
	// An OTA with no DSC-bearing cryptexes is a source that does not apply,
	// not a failure. Recording it would mark every delta OTA incomplete.
	//
	// The sentinel arrives joined with any temp-dir cleanup failure, so the
	// leaf is filtered out of the join rather than the whole error discarded:
	// short-circuiting on errors.Is would drop a real leaked temp dir.
	for _, e := range flattenErrors(err) {
		if errors.Is(e, ota.ErrNoDscInCryptexes) {
			log.WithError(e).Debug("no dyld_shared_cache in OTA cryptexes")
			continue
		}
		rep.addErrors(ota.PhaseCryptexDiscovery, "", e)
	}
}

func dscFromAssets(src dscSource, opts dscOptions, rep *dscReport) {
	log.Info("Searching OTA asset files for dyld_shared_cache files")
	for _, name := range src.AssetNames() {
		if !matchesPostBOMPattern(opts.pattern, name) {
			continue
		}
		fname, err := outputPathForExtraction(opts.Output, name, false)
		if err != nil {
			rep.addErrors(ota.PhaseCopy, sourceOTAAsset, err)
			continue
		}
		if err := src.CopyAsset(name, fname); err != nil {
			// copyOTAFileToPath renames into place, so a failure never disturbs a
			// file an earlier source already reported at this path.
			rep.addErrors(ota.PhaseCopy, sourceOTAAsset, err)
			continue
		}
		rep.addFile(opts.ReportRoot, fname, sourceOTAAsset)
	}
}

func dscFromPayloads(src dscSource, opts dscOptions, rep *dscReport) {
	if !payloadConsent(src, opts) {
		return
	}
	utils.Indent(log.Info, 2)(fmt.Sprintf("Searching for '%s' in OTA payload files", opts.pattern.String()))
	err := src.GetPayloadFilesWithCallback(opts.pattern.String(), opts.PayloadRange, opts.Output, func(dst string) {
		rep.addFile(opts.ReportRoot, dst, sourcePayloadV2)
	})
	if err != nil {
		rep.addErrors(ota.PhasePayloadExtract, sourcePayloadV2, err)
	}
}

// payloadConsent decides whether the payloadv2 source may run. The post.bom
// pre-filter lives here because its only purpose is deciding whether asking a
// human is worth it; with no human to ask its only effect is a false negative.
func payloadConsent(src dscSource, opts dscOptions) bool {
	if opts.Prompt == nil {
		return true
	}
	found := false
	for _, name := range src.PostBOMNames() {
		if matchesPostBOMPattern(opts.pattern, name) {
			utils.Indent(log.Warn, 2)(fmt.Sprintf(
				"Found '%s' in post.bom (most likely in payloadv2 files)", filepath.Base(name)))
			found = true
		}
	}
	if !found {
		return false
	}
	return opts.Prompt(fmt.Sprintf("Search for '%s' in payloadv2 files?", opts.pattern.String()))
}

func dscPatternForArches(arches []string) *regexp.Regexp {
	if len(arches) == 0 {
		return reDSCUber
	}

	var dyldArches []string
	wantAOT := false
	for _, arch := range arches {
		if arch == "aot" {
			wantAOT = true
			continue
		}
		quoted := regexp.QuoteMeta(arch)
		if !slices.Contains(dyldArches, quoted) {
			dyldArches = append(dyldArches, quoted)
		}
	}

	var patterns []string
	if len(dyldArches) > 0 {
		patterns = append(patterns,
			`((System/DriverKit/|System/x86Support/)?System/Library/(dyld|Caches/com\.apple\.dyld)/dyld_shared_cache_(`+
				strings.Join(dyldArches, "|")+`)`+dyld.CacheRegexEnding+`)`)
	}
	if wantAOT {
		patterns = append(patterns, `(System/Library/dyld/aot_shared_cache\.[0-9]+$)`)
	}
	return regexp.MustCompile(strings.Join(patterns, "|"))
}

func confirmPayloadSearch(question string) bool {
	cont := false
	if err := survey.AskOne(&survey.Confirm{Message: question}, &cont); err != nil {
		log.WithError(err).Warn("payloadv2 search prompt failed; skipping " +
			"(pass --confirm or --json to search non-interactively)")
		return false
	}
	return cont
}

// writeDSCReport buffers the whole document before touching w, so a partial
// write can never leave malformed JSON on stdout.
func writeDSCReport(w io.Writer, rep *dscReport) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rep); err != nil {
		return fmt.Errorf("failed to encode dyld_shared_cache report: %w", err)
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write dyld_shared_cache report: %w", err)
	}
	return nil
}

// logDSCReport renders the report for humans. Entry paths are relative to the
// report root, so they are rejoined with it: logging them bare hides the
// --output directory the files actually landed in. The join is printed as-is
// rather than relative to the cwd, which turns a distant --output into an
// unreadable stack of "..".
func logDSCReport(root string, rep *dscReport) {
	for _, f := range rep.Files {
		utils.Indent(log.Info, 2)(filepath.Join(root, filepath.FromSlash(f.Path)))
	}
	for _, e := range rep.Errors {
		utils.Indent(log.Error, 2)(fmt.Sprintf("[%s] %s", e.Phase, e.Message))
	}
}

func dscReportPath(root, dst string) string {
	rel, err := filepath.Rel(root, dst)
	if err != nil {
		return filepath.ToSlash(filepath.Clean(dst))
	}
	return filepath.ToSlash(rel)
}

func dscArch(p string) string {
	arch, _ := ota.DSCFileArch(p)
	return arch
}

func flattenErrors(err error) []error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var out []error
		for _, e := range joined.Unwrap() {
			out = append(out, flattenErrors(e)...)
		}
		return out
	}
	return []error{err}
}

// otaDSCSource adapts *ota.AA to dscSource. ExtractFromCryptexesWithSources and
// GetPayloadFilesWithCallback are promoted from the embedded reader.
type otaDSCSource struct {
	*ota.AA
	decomp bool
}

func (s otaDSCSource) AssetNames() []string {
	files := s.Files()
	out := make([]string, 0, len(files))
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		out = append(out, f.Name())
	}
	return out
}

func (s otaDSCSource) PostBOMNames() []string {
	// A full OTA's post.bom runs to ~10^5 entries, so growing this one append
	// at a time costs tens of MB in reallocation.
	post := s.PostFiles()
	out := make([]string, 0, len(post))
	for _, f := range post {
		if f.IsDir() {
			continue
		}
		out = append(out, f.Name())
	}
	return out
}

func (s otaDSCSource) CopyAsset(name, outputPath string) error {
	return copyOTAFileToPath(s.AA, name, s.decomp, outputPath)
}
