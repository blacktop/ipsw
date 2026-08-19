package ota

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/ota"
)

type fakeDSCSource struct {
	cryptexFiles []ota.ExtractedFile
	cryptexErr   error
	assets       []string
	postBOM      []string
	payload      []string
	payloadErr   error
	copyErr      error

	copied        []string
	payloadCalls  int
	cryptexArches [][]string
}

func (f *fakeDSCSource) ExtractFromCryptexesWithSourcesForArches(pattern, output string, arches []string) ([]ota.ExtractedFile, error) {
	f.cryptexArches = append(f.cryptexArches, append([]string(nil), arches...))
	re := regexp.MustCompile(pattern)
	var out []ota.ExtractedFile
	for _, file := range f.cryptexFiles {
		if re.MatchString(file.Path) {
			out = append(out, file)
		}
	}
	return out, f.cryptexErr
}

func (f *fakeDSCSource) GetPayloadFilesWithCallback(pattern, payloadRange, output string, onFile func(dst string)) error {
	f.payloadCalls++
	re := regexp.MustCompile(pattern)
	for _, p := range f.payload {
		if re.MatchString(p) && onFile != nil {
			onFile(p)
		}
	}
	return f.payloadErr
}

func (f *fakeDSCSource) AssetNames() []string   { return f.assets }
func (f *fakeDSCSource) PostBOMNames() []string { return f.postBOM }

func (f *fakeDSCSource) CopyAsset(name, outputPath string) error {
	if f.copyErr != nil {
		return f.copyErr
	}
	f.copied = append(f.copied, outputPath)
	return nil
}

func testOpts() dscOptions {
	return dscOptions{Output: "out/24G720__MacOS", ReportRoot: "out"}
}

func TestExtractDSCCryptexSuccessStopsThere(t *testing.T) {
	src := &fakeDSCSource{
		cryptexFiles: []ota.ExtractedFile{
			{Path: "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e", Source: "cryptex-system-arm64e"},
			{Path: "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e.01", Source: "cryptex-system-arm64e"},
		},
		assets:  []string{"AssetData/boot/System/Library/dyld/dyld_shared_cache_arm64e"},
		postBOM: []string{"System/Library/dyld/dyld_shared_cache_arm64e"},
		payload: []string{"out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e"},
	}

	rep := extractDSC(src, testOpts())

	if !rep.Complete {
		t.Fatalf("report.Complete = false, errors = %+v", rep.Errors)
	}
	if len(rep.Files) != 2 {
		t.Fatalf("report.Files = %+v, want 2 entries", rep.Files)
	}
	if len(rep.Errors) != 0 {
		t.Fatalf("report.Errors = %+v, want none", rep.Errors)
	}
	if src.payloadCalls != 0 {
		t.Errorf("payload source ran %d time(s), want 0", src.payloadCalls)
	}
	if len(src.copied) != 0 {
		t.Errorf("asset source copied %v, want nothing", src.copied)
	}
	for _, f := range rep.Files {
		if f.Source != "cryptex-system-arm64e" {
			t.Errorf("file %q source = %q, want cryptex-system-arm64e", f.Path, f.Source)
		}
		if f.Arch != "arm64e" {
			t.Errorf("file %q arch = %q, want arm64e", f.Path, f.Arch)
		}
	}
	if want := "24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e"; rep.Files[0].Path != want {
		t.Errorf("file path = %q, want %q", rep.Files[0].Path, want)
	}
}

func TestExtractDSCRequestedArchCanComeFromDifferentlyNamedCryptex(t *testing.T) {
	src := &fakeDSCSource{cryptexFiles: []ota.ExtractedFile{{
		Path:   "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_x86_64",
		Source: "cryptex-system-arm64e",
	}}}
	opts := testOpts()
	opts.Arches = []string{"x86_64"}

	rep := extractDSC(src, opts)

	if !rep.Complete {
		t.Fatalf("report.Complete = false, errors = %+v", rep.Errors)
	}
	if len(rep.Files) != 1 {
		t.Fatalf("report.Files = %+v, want one x86_64 entry", rep.Files)
	}
	if got := rep.Files[0]; got.Arch != "x86_64" || got.Source != "cryptex-system-arm64e" {
		t.Fatalf("report file = {arch:%q source:%q}, want {x86_64 cryptex-system-arm64e}",
			got.Arch, got.Source)
	}
	if src.payloadCalls != 0 || len(src.copied) != 0 {
		t.Fatalf("later sources ran after x86_64 was covered: asset=%v payload=%d",
			src.copied, src.payloadCalls)
	}
}

// TestExtractDSCSidecarOnlyDoesNotSatisfyArch pins that a .symbols (or any
// other sidecar) alone does not count as coverage for its architecture: the
// primary cache is what dyld loads, so later sources must still run and its
// absence must still be reported.
func TestExtractDSCSidecarOnlyDoesNotSatisfyArch(t *testing.T) {
	src := &fakeDSCSource{cryptexFiles: []ota.ExtractedFile{{
		Path:   "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e.symbols",
		Source: "cryptex-system-arm64e",
	}}}
	opts := testOpts()
	opts.Arches = []string{"arm64e"}

	rep := extractDSC(src, opts)

	if rep.Complete {
		t.Fatal("report.Complete = true with only a sidecar materialized")
	}
	if src.payloadCalls != 1 {
		t.Errorf("payload source ran %d time(s), want the fallback attempted", src.payloadCalls)
	}
	if missing := rep.missingArches(opts.Arches); len(missing) != 1 || missing[0] != "arm64e" {
		t.Fatalf("missingArches() = %v, want [arm64e]", missing)
	}
	if rep.fatalErr() == nil {
		t.Error("fatalErr() = nil; the requested primary cache is missing")
	}
}

func TestExtractDSCRequestedArchesFallThroughUntilCovered(t *testing.T) {
	src := &fakeDSCSource{
		cryptexFiles: []ota.ExtractedFile{{
			Path:   "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e",
			Source: "cryptex-system-arm64e",
		}},
		assets: []string{
			"System/Library/dyld/dyld_shared_cache_x86_64",
			"System/Library/dyld/dyld_shared_cache_arm64_32",
		},
		payload: []string{"out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_aot"},
	}
	opts := testOpts()
	opts.Arches = []string{"arm64e", "x86_64"}

	rep := extractDSC(src, opts)

	if !rep.Complete {
		t.Fatalf("report.Complete = false, errors = %+v", rep.Errors)
	}
	if len(rep.Files) != 2 {
		t.Fatalf("report.Files = %+v, want the two requested cache families", rep.Files)
	}
	for _, arch := range opts.Arches {
		if len(rep.missingArches([]string{arch})) != 0 {
			t.Errorf("requested architecture %q is missing from %+v", arch, rep.Files)
		}
	}
	if len(src.copied) != 1 || !strings.HasSuffix(src.copied[0], "dyld_shared_cache_x86_64") {
		t.Fatalf("asset copies = %v, want only the selected x86_64 cache", src.copied)
	}
	if src.payloadCalls != 0 {
		t.Errorf("payload source ran %d time(s) after all requested architectures were covered", src.payloadCalls)
	}
	if len(src.cryptexArches) != 1 || strings.Join(src.cryptexArches[0], ",") != "arm64e,x86_64" {
		t.Errorf("cryptex architecture filter = %v, want [arm64e x86_64]", src.cryptexArches)
	}
}

func TestExtractDSCAbsentRequestedArchHasStructuralDiscoveryOutcome(t *testing.T) {
	src := &fakeDSCSource{}
	opts := testOpts()
	opts.Arches = []string{"x86_64"}

	rep := extractDSC(src, opts)

	if rep.Complete {
		t.Fatal("report.Complete = true with x86_64 absent")
	}
	if len(rep.Files) != 0 {
		t.Fatalf("report.Files = %+v, want none", rep.Files)
	}
	if len(rep.Errors) != 1 {
		t.Fatalf("report.Errors = %+v, want one absence entry", rep.Errors)
	}
	if got := rep.Errors[0]; got.Phase != ota.PhaseDSCDiscovery || got.Source != "" {
		t.Fatalf("absence error = {phase:%q source:%q}, want {dsc-discovery <empty>}",
			got.Phase, got.Source)
	}
	if rep.fatalErr() == nil {
		t.Fatal("fatalErr() = nil for an explicitly requested architecture")
	}
	if src.payloadCalls != 1 {
		t.Fatalf("payload source ran %d time(s), want exhaustive final fallback", src.payloadCalls)
	}
}

func TestExtractDSCMissingRequestedArchIsFatal(t *testing.T) {
	src := &fakeDSCSource{
		cryptexFiles: []ota.ExtractedFile{{
			Path:   "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e",
			Source: "cryptex-system-arm64e",
		}},
	}
	opts := testOpts()
	opts.Arches = []string{"arm64e", "x86_64"}

	rep := extractDSC(src, opts)

	if rep.Complete {
		t.Fatal("report.Complete = true with x86_64 still missing")
	}
	if len(rep.Files) != 1 || rep.Files[0].Arch != "arm64e" {
		t.Fatalf("report.Files = %+v, want the partial arm64e result", rep.Files)
	}
	if len(rep.Errors) != 1 || rep.Errors[0].Phase != ota.PhaseDSCDiscovery {
		t.Fatalf("report.Errors = %+v, want one dsc-discovery error", rep.Errors)
	}
	if !strings.Contains(rep.Errors[0].Message, "x86_64") {
		t.Errorf("missing-architecture message = %q, want x86_64", rep.Errors[0].Message)
	}
	if rep.fatalErr() == nil {
		t.Error("fatalErr() = nil; an explicitly requested architecture is missing")
	}
	if src.payloadCalls != 1 {
		t.Errorf("payload source ran %d time(s), want the final fallback attempted", src.payloadCalls)
	}
}

func TestExtractDSCFallsBackThroughAssetsToPayloads(t *testing.T) {
	src := &fakeDSCSource{
		cryptexErr: fmt.Errorf("wrapped: %w", ota.ErrNoDscInCryptexes),
		payload: []string{
			"out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e",
			"out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e.symbols",
		},
	}

	rep := extractDSC(src, testOpts())

	if !rep.Complete {
		t.Fatalf("report.Complete = false, errors = %+v", rep.Errors)
	}
	if len(rep.Errors) != 0 {
		t.Fatalf("report.Errors = %+v, want none (ErrNoDscInCryptexes is not a failure)", rep.Errors)
	}
	if src.payloadCalls != 1 {
		t.Fatalf("payload source ran %d time(s), want 1", src.payloadCalls)
	}
	if len(rep.Files) != 2 {
		t.Fatalf("report.Files = %+v, want 2 entries", rep.Files)
	}
	for _, f := range rep.Files {
		if f.Source != sourcePayloadV2 {
			t.Errorf("file %q source = %q, want %q", f.Path, f.Source, sourcePayloadV2)
		}
	}
}

func TestExtractDSCPartialFailureKeepsFilesAndErrors(t *testing.T) {
	src := &fakeDSCSource{
		cryptexFiles: []ota.ExtractedFile{
			{Path: "out/24G720__MacOS/System/Library/dyld/aot_shared_cache.0", Source: "cryptex-system-rosetta"},
		},
		cryptexErr: errors.Join(&ota.PhaseError{
			Phase:  ota.PhaseMount,
			Source: "cryptex-system-arm64e",
			Err:    errors.New("hdiutil: attach failed - Resource busy"),
		}),
	}

	rep := extractDSC(src, testOpts())

	if rep.Complete {
		t.Fatal("report.Complete = true, want false")
	}
	if len(rep.Files) != 1 {
		t.Fatalf("report.Files = %+v, want 1 entry", rep.Files)
	}
	if len(rep.Errors) != 1 {
		t.Fatalf("report.Errors = %+v, want 1 entry", rep.Errors)
	}
	if rep.Errors[0].Phase != ota.PhaseMount {
		t.Errorf("error phase = %q, want %q", rep.Errors[0].Phase, ota.PhaseMount)
	}
	if rep.Errors[0].Source != "cryptex-system-arm64e" {
		t.Errorf("error source = %q, want cryptex-system-arm64e", rep.Errors[0].Source)
	}
	if rep.fatalErr() == nil {
		t.Error("fatalErr() = nil, want the mount failure")
	}
}

// TestExtractDSCCleanupFailureDoesNotRerunLaterSources pins that a failure
// which happens AFTER every file was copied (a failed unmount) does not send
// extractDSC back through the asset and payloadv2 sources: nothing is missing,
// so re-running the payloadv2 scan would only burn minutes and re-list files
// that are already in the report.
func TestExtractDSCCleanupFailureDoesNotRerunLaterSources(t *testing.T) {
	copied := []ota.ExtractedFile{
		{Path: "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e", Source: "cryptex-system-arm64e"},
		{Path: "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e.01", Source: "cryptex-system-arm64e"},
	}
	src := &fakeDSCSource{
		cryptexFiles: copied,
		cryptexErr: &ota.PhaseError{
			Phase:  ota.PhaseCleanup,
			Source: "cryptex-system-arm64e",
			Err:    errors.New("hdiutil: detach failed - Resource busy"),
		},
		assets:  []string{"System/Library/dyld/dyld_shared_cache_arm64e"},
		payload: []string{"out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e"},
	}

	rep := extractDSC(src, testOpts())

	if src.payloadCalls != 0 {
		t.Errorf("payload source ran %d time(s) after a post-copy cleanup failure, want 0", src.payloadCalls)
	}
	if len(src.copied) != 0 {
		t.Errorf("asset source copied %v after a post-copy cleanup failure, want nothing", src.copied)
	}
	if len(rep.Files) != len(copied) {
		t.Fatalf("report.Files = %+v, want %d entries", rep.Files, len(copied))
	}
	seen := map[string]bool{}
	for _, f := range rep.Files {
		if seen[f.Path] {
			t.Errorf("report lists %q twice", f.Path)
		}
		seen[f.Path] = true
	}
	// The cleanup failure is still reported and still fails the command.
	if rep.Complete {
		t.Error("report.Complete = true, want false")
	}
	if len(rep.Errors) != 1 || rep.Errors[0].Phase != ota.PhaseCleanup {
		t.Fatalf("report.Errors = %+v, want a single cleanup entry", rep.Errors)
	}
	if rep.fatalErr() == nil {
		t.Error("fatalErr() = nil, want the unmount failure")
	}
}

// TestExtractDSCCleanupFailureSurvivesTheNoDSCSentinel pins that the "this
// source does not apply" sentinel only suppresses itself. ota.Reader joins the
// temp-dir removal result onto whatever it is about to return, so a delta OTA
// whose staging temp dir cannot be removed hands back
// errors.Join(ErrNoDscInCryptexes, cleanup). Matching the sentinel with
// errors.Is and returning would discard the cleanup leaf, and the report would
// claim complete:true over a leaked temp dir holding a multi-GB staged cryptex.
func TestExtractDSCCleanupFailureSurvivesTheNoDSCSentinel(t *testing.T) {
	cleanup := &ota.PhaseError{
		Phase: ota.PhaseCleanup,
		Err:   errors.New("failed to remove temp dir /var/folders/9k/T/ota_extract_cryptexes123: permission denied"),
	}
	src := &fakeDSCSource{
		cryptexErr: errors.Join(ota.ErrNoDscInCryptexes, cleanup),
		assets:     []string{"System/Library/dyld/dyld_shared_cache_arm64e"},
		payload:    []string{"out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e"},
	}

	rep := extractDSC(src, testOpts())

	// The sentinel itself is still suppressed: the asset source succeeded, so
	// the only error may be the cleanup failure.
	if len(rep.Errors) != 1 || rep.Errors[0].Phase != ota.PhaseCleanup {
		t.Fatalf("report.Errors = %+v, want exactly the cleanup failure", rep.Errors)
	}
	if !strings.Contains(rep.Errors[0].Message, "failed to remove temp dir") {
		t.Errorf("error message = %q, want the leaked temp dir named", rep.Errors[0].Message)
	}
	if rep.Complete {
		t.Error("report.Complete = true over a leaked temp dir, want false")
	}
	if rep.fatalErr() == nil {
		t.Error("fatalErr() = nil; a leaked temp dir must drive a non-zero exit")
	}
	if len(rep.Files) != 1 || rep.Files[0].Source != sourceOTAAsset {
		t.Fatalf("report.Files = %+v, want the one asset-sourced cache", rep.Files)
	}
	if src.payloadCalls != 0 {
		t.Errorf("payload source ran %d time(s) after a post-copy cleanup failure, want 0", src.payloadCalls)
	}
}

// TestExtractDSCNoDSCSentinelAloneRecordsNothing is the control for the test
// above: the bare sentinel, however it is wrapped, must never reach the report.
func TestExtractDSCNoDSCSentinelAloneRecordsNothing(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "bare", err: ota.ErrNoDscInCryptexes},
		{name: "wrapped", err: fmt.Errorf("cryptex scan: %w", ota.ErrNoDscInCryptexes)},
		{name: "joined with itself", err: errors.Join(ota.ErrNoDscInCryptexes)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := &fakeDSCSource{
				cryptexErr: tt.err,
				assets:     []string{"System/Library/dyld/dyld_shared_cache_arm64e"},
			}

			rep := extractDSC(src, testOpts())

			if !rep.Complete {
				t.Fatalf("report.Complete = false, errors = %+v", rep.Errors)
			}
			if len(rep.Errors) != 0 {
				t.Fatalf("report.Errors = %+v, want none", rep.Errors)
			}
		})
	}
}

// TestExtractDSCMountFailureStillFallsThrough is the companion to the cleanup
// case: a failure that happens BEFORE the copy means an architecture may still
// be missing, so the later sources must run.
func TestExtractDSCMountFailureStillFallsThrough(t *testing.T) {
	src := &fakeDSCSource{
		cryptexFiles: []ota.ExtractedFile{
			{Path: "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_x86_64", Source: "cryptex-system-rosetta"},
		},
		cryptexErr: &ota.PhaseError{
			Phase:  ota.PhaseMount,
			Source: "cryptex-system-arm64e",
			Err:    errors.New("hdiutil: attach failed - Resource busy"),
		},
		payload: []string{"out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e"},
	}

	rep := extractDSC(src, testOpts())

	if src.payloadCalls != 1 {
		t.Fatalf("payload source ran %d time(s) after a pre-copy mount failure, want 1", src.payloadCalls)
	}
	if len(rep.Files) != 2 {
		t.Fatalf("report.Files = %+v, want the rosetta and the recovered payloadv2 entry", rep.Files)
	}
}

// TestExtractDSCFallThroughDoesNotDuplicatePaths pins the report invariant when
// the payloadv2 rescan re-materializes a path a partly-failed cryptex already
// wrote: one entry per path, attributed to the source that wrote it last.
func TestExtractDSCFallThroughDoesNotDuplicatePaths(t *testing.T) {
	const shared = "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_x86_64"
	src := &fakeDSCSource{
		cryptexFiles: []ota.ExtractedFile{
			{Path: shared, Source: "cryptex-system-rosetta"},
		},
		cryptexErr: &ota.PhaseError{
			Phase:  ota.PhaseMount,
			Source: "cryptex-system-arm64e",
			Err:    errors.New("hdiutil: attach failed - Resource busy"),
		},
		// The rescan uses the uber regex, so it re-extracts every cache it
		// finds, including the one the cryptex source already produced.
		payload: []string{shared, "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e"},
	}

	rep := extractDSC(src, testOpts())

	seen := map[string]int{}
	for _, f := range rep.Files {
		seen[f.Path]++
	}
	for path, n := range seen {
		if n > 1 {
			t.Errorf("report lists %q %d times, want 1", path, n)
		}
	}
	if len(rep.Files) != 2 {
		t.Fatalf("report.Files = %+v, want 2 distinct paths", rep.Files)
	}
	for _, f := range rep.Files {
		if f.Path == "24G720__MacOS/System/Library/dyld/dyld_shared_cache_x86_64" && f.Source != sourcePayloadV2 {
			t.Errorf("source = %q for the rewritten path, want %q (last writer owns the bytes)", f.Source, sourcePayloadV2)
		}
	}
}

func TestExtractDSCFlattensJoinedErrors(t *testing.T) {
	src := &fakeDSCSource{
		cryptexErr: errors.Join(
			&ota.PhaseError{Phase: ota.PhaseCryptexPatch, Source: "cryptex-system-arm64", Err: errors.New("a")},
			errors.Join(
				&ota.PhaseError{Phase: ota.PhaseMount, Source: "cryptex-system-arm64e", Err: errors.New("b")},
				&ota.PhaseError{Phase: ota.PhaseCleanup, Source: "cryptex-system-rosetta", Err: errors.New("c")},
			),
		),
	}

	rep := extractDSC(src, testOpts())

	wantPhases := []ota.Phase{
		ota.PhaseCryptexPatch,
		ota.PhaseMount,
		ota.PhaseCleanup,
		ota.PhaseDSCDiscovery, // terminal "materialized nothing"
	}
	if len(rep.Errors) != len(wantPhases) {
		t.Fatalf("report.Errors = %+v, want %d entries", rep.Errors, len(wantPhases))
	}
	for i, want := range wantPhases {
		if rep.Errors[i].Phase != want {
			t.Errorf("error[%d].Phase = %q, want %q", i, rep.Errors[i].Phase, want)
		}
	}
}

func TestExtractDSCDefaultsPhaseForPlainErrors(t *testing.T) {
	src := &fakeDSCSource{cryptexErr: errors.New("boom")}

	rep := extractDSC(src, testOpts())

	if len(rep.Errors) != 2 {
		t.Fatalf("report.Errors = %+v, want 2 entries", rep.Errors)
	}
	if rep.Errors[0].Phase != ota.PhaseCryptexDiscovery {
		t.Errorf("error phase = %q, want %q", rep.Errors[0].Phase, ota.PhaseCryptexDiscovery)
	}
	if rep.Errors[0].Source != "" {
		t.Errorf("error source = %q, want empty", rep.Errors[0].Source)
	}
}

func TestExtractDSCZeroFilesIsAnError(t *testing.T) {
	rep := extractDSC(&fakeDSCSource{}, testOpts())

	if rep.Complete {
		t.Fatal("report.Complete = true, want false")
	}
	if rep.Files == nil || len(rep.Files) != 0 {
		t.Fatalf("report.Files = %+v, want empty non-nil slice", rep.Files)
	}
	if len(rep.Errors) != 1 {
		t.Fatalf("report.Errors = %+v, want 1 entry", rep.Errors)
	}
	if rep.Errors[0].Phase != ota.PhaseDSCDiscovery {
		t.Errorf("error phase = %q, want %q", rep.Errors[0].Phase, ota.PhaseDSCDiscovery)
	}
	if err := rep.fatalErr(); err != nil {
		t.Errorf("fatalErr() = %v, want nil (human mode exit code must not change)", err)
	}
}

func TestExtractDSCFatalErrExcludesOnlyNoDSCSentinel(t *testing.T) {
	mount := &ota.PhaseError{Phase: ota.PhaseMount, Source: "cryptex-system-arm64e", Err: errors.New("busy")}

	tests := []struct {
		name    string
		src     *fakeDSCSource
		wantErr bool
	}{
		{
			name: "no files and only the sentinel",
			src:  &fakeDSCSource{},
		},
		{
			name:    "no files plus a real failure",
			src:     &fakeDSCSource{cryptexErr: mount},
			wantErr: true,
		},
		{
			name: "files plus a real failure",
			src: &fakeDSCSource{
				cryptexFiles: []ota.ExtractedFile{{Path: "out/f/dyld_shared_cache_arm64", Source: "cryptex-system-arm64"}},
				cryptexErr:   mount,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDSC(tt.src, testOpts()).fatalErr()
			if tt.wantErr && got == nil {
				t.Fatal("fatalErr() = nil, want error")
			}
			if !tt.wantErr && got != nil {
				t.Fatalf("fatalErr() = %v, want nil", got)
			}
		})
	}
}

func TestExtractDSCNeverPromptsWhenPromptIsNil(t *testing.T) {
	src := &fakeDSCSource{}
	opts := testOpts()

	extractDSC(src, opts)

	if src.payloadCalls != 1 {
		t.Fatalf("payload source ran %d time(s) with a nil Prompt and an empty post.bom, want 1", src.payloadCalls)
	}

	interactive := &fakeDSCSource{}
	opts.Prompt = func(string) bool {
		t.Fatal("prompt asked despite an empty post.bom")
		return true
	}
	extractDSC(interactive, opts)
	if interactive.payloadCalls != 0 {
		t.Fatalf("payload source ran %d time(s) in interactive mode with an empty post.bom, want 0", interactive.payloadCalls)
	}
}

func TestExtractDSCPromptDeclineSkipsPayload(t *testing.T) {
	src := &fakeDSCSource{postBOM: []string{"System/Library/dyld/dyld_shared_cache_arm64e"}}
	opts := testOpts()
	asked := 0
	opts.Prompt = func(string) bool {
		asked++
		return false
	}

	rep := extractDSC(src, opts)

	if asked != 1 {
		t.Fatalf("prompt asked %d time(s), want 1", asked)
	}
	if src.payloadCalls != 0 {
		t.Fatalf("payload source ran %d time(s) after a declined prompt, want 0", src.payloadCalls)
	}
	if len(rep.Files) != 0 {
		t.Fatalf("report.Files = %+v, want none", rep.Files)
	}
	if len(rep.Errors) != 1 || rep.Errors[0].Phase != ota.PhaseDSCDiscovery {
		t.Fatalf("report.Errors = %+v, want a single dsc-discovery entry", rep.Errors)
	}
	if err := rep.fatalErr(); err != nil {
		t.Errorf("fatalErr() = %v, want nil", err)
	}
}

func TestExtractDSCAssetSourceRecordsCopyErrors(t *testing.T) {
	src := &fakeDSCSource{
		cryptexErr: ota.ErrNoDscInCryptexes,
		assets:     []string{"AssetData/boot/System/Library/dyld/dyld_shared_cache_arm64e"},
		copyErr:    errors.New("no space left on device"),
		payload:    []string{"out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e"},
	}

	rep := extractDSC(src, testOpts())

	if len(rep.Errors) != 1 {
		t.Fatalf("report.Errors = %+v, want 1 entry", rep.Errors)
	}
	if rep.Errors[0].Phase != ota.PhaseCopy {
		t.Errorf("error phase = %q, want %q", rep.Errors[0].Phase, ota.PhaseCopy)
	}
	if rep.Errors[0].Source != sourceOTAAsset {
		t.Errorf("error source = %q, want %q", rep.Errors[0].Source, sourceOTAAsset)
	}
	if src.payloadCalls != 1 {
		t.Errorf("payload source ran %d time(s), want 1", src.payloadCalls)
	}
	if len(rep.Files) != 1 || rep.Files[0].Source != sourcePayloadV2 {
		t.Fatalf("report.Files = %+v, want one payloadv2 entry", rep.Files)
	}
}

// TestExtractDSCMessagePrefixIsNotGuaranteed pins that `message` has no single
// shape. ota.PhaseError.Error() prefixes "<source>: <phase>: " only when the
// failure was attributed inside pkg/ota; a plain error recorded against a
// caller-supplied default source keeps a non-empty `source` and an UNPREFIXED
// message. The JSON guide therefore tells consumers never to parse `message`.
func TestExtractDSCMessagePrefixIsNotGuaranteed(t *testing.T) {
	t.Run("attributed inside pkg/ota is prefixed", func(t *testing.T) {
		src := &fakeDSCSource{cryptexErr: &ota.PhaseError{
			Phase:  ota.PhaseMount,
			Source: "cryptex-system-arm64e",
			Err:    errors.New("hdiutil: attach failed - Resource busy"),
		}}

		got := extractDSC(src, testOpts()).Errors[0]

		if want := "cryptex-system-arm64e: mount: "; !strings.HasPrefix(got.Message, want) {
			t.Fatalf("message = %q, want the %q prefix", got.Message, want)
		}
	})

	t.Run("asset copy failure has a source but no prefix", func(t *testing.T) {
		src := &fakeDSCSource{
			cryptexErr: ota.ErrNoDscInCryptexes,
			assets:     []string{"AssetData/boot/System/Library/dyld/dyld_shared_cache_arm64e"},
			copyErr:    errors.New("failed to open file 'AssetData/boot/...' in OTA: bad magic"),
		}

		got := extractDSC(src, testOpts()).Errors[0]

		if got.Source != sourceOTAAsset || got.Phase != ota.PhaseCopy {
			t.Fatalf("entry = {phase:%q source:%q}, want {copy ota-asset}", got.Phase, got.Source)
		}
		if strings.HasPrefix(got.Message, string(got.Source)+": ") {
			t.Fatalf("message = %q is prefixed; the guide documents this entry as unprefixed", got.Message)
		}
		if !strings.HasPrefix(got.Message, "failed to open file ") {
			t.Fatalf("message = %q, want the bare underlying error", got.Message)
		}
	})

	t.Run("payload failure without an inner source has a source but no prefix", func(t *testing.T) {
		src := &fakeDSCSource{
			cryptexErr: ota.ErrNoDscInCryptexes,
			// wrapPhase(PhasePayloadExtract, "", ...) attributes no member, so
			// PhaseError.Error() returns the bare message; dscFromPayloads then
			// stamps the default "payloadv2" source onto the entry.
			payloadErr: &ota.PhaseError{
				Phase: ota.PhasePayloadExtract,
				Err:   errors.New(`exec: "aa": executable file not found in $PATH`),
			},
		}

		got := extractDSC(src, testOpts()).Errors[0]

		if got.Source != sourcePayloadV2 {
			t.Fatalf("source = %q, want %q", got.Source, sourcePayloadV2)
		}
		if strings.Contains(got.Message, string(ota.PhasePayloadExtract)+": ") {
			t.Fatalf("message = %q is prefixed; the guide documents this entry as unprefixed", got.Message)
		}
	})
}

func TestExtractDSCAssetSourceMaterializesFiles(t *testing.T) {
	src := &fakeDSCSource{
		cryptexErr: ota.ErrNoDscInCryptexes,
		assets: []string{
			"System/Library/dyld/dyld_shared_cache_arm64e",
			"AssetData/Info.plist",
		},
	}
	opts := testOpts()

	rep := extractDSC(src, opts)

	if !rep.Complete {
		t.Fatalf("report.Complete = false, errors = %+v", rep.Errors)
	}
	if src.payloadCalls != 0 {
		t.Errorf("payload source ran %d time(s) after the asset source succeeded, want 0", src.payloadCalls)
	}
	want := []dscFileEntry{{
		Path:   "24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e",
		Arch:   "arm64e",
		Source: sourceOTAAsset,
	}}
	if len(rep.Files) != 1 || rep.Files[0] != want[0] {
		t.Fatalf("report.Files = %+v, want %+v", rep.Files, want)
	}
}

const wantFullSuccessReport = `{"schema_version":1,"complete":true,"files":[{"path":"24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e","arch":"arm64e","source":"cryptex-system-arm64e"},{"path":"24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e.01","arch":"arm64e","source":"cryptex-system-arm64e"},{"path":"24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e.symbols","arch":"arm64e","source":"cryptex-system-arm64e"},{"path":"24G720__MacOS/System/Library/dyld/aot_shared_cache.0","arch":"aot","source":"cryptex-system-rosetta"},{"path":"24G720__MacOS/System/Library/dyld/dyld_shared_cache_x86_64","arch":"x86_64","source":"cryptex-system-rosetta"}],"errors":[]}`

func TestWriteDSCReportFullSuccess(t *testing.T) {
	rep := newDSCReport()
	for _, f := range []ota.ExtractedFile{
		{Path: "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e", Source: "cryptex-system-arm64e"},
		{Path: "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e.01", Source: "cryptex-system-arm64e"},
		{Path: "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e.symbols", Source: "cryptex-system-arm64e"},
		{Path: "out/24G720__MacOS/System/Library/dyld/aot_shared_cache.0", Source: "cryptex-system-rosetta"},
		{Path: "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_x86_64", Source: "cryptex-system-rosetta"},
	} {
		rep.addFile("out", f.Path, f.Source)
	}
	assertReport(t, rep.finish(), wantFullSuccessReport)
}

const wantPartialSuccessReport = `{"schema_version":1,"complete":false,"files":[{"path":"24G720__MacOS/System/Library/dyld/aot_shared_cache.0","arch":"aot","source":"cryptex-system-rosetta"},{"path":"24G720__MacOS/System/Library/dyld/dyld_shared_cache_x86_64","arch":"x86_64","source":"cryptex-system-rosetta"}],"errors":[{"phase":"mount","source":"cryptex-system-arm64e","message":"cryptex-system-arm64e: mount: failed to mount /var/folders/9k/T/ota_extract_cryptexes123/cryptex-system-arm64e.dmg: hdiutil: attach failed - Resource busy"},{"phase":"cleanup","source":"cryptex-system-rosetta","message":"cryptex-system-rosetta: cleanup: failed to unmount /tmp/cryptex-system-rosetta.dmg.mount: hdiutil: detach failed - Resource busy"}]}`

func TestWriteDSCReportPartialSuccess(t *testing.T) {
	rep := newDSCReport()
	rep.addFile("out", "out/24G720__MacOS/System/Library/dyld/aot_shared_cache.0", "cryptex-system-rosetta")
	rep.addFile("out", "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_x86_64", "cryptex-system-rosetta")
	rep.addErrors(ota.PhaseCryptexDiscovery, "", errors.Join(
		&ota.PhaseError{
			Phase:  ota.PhaseMount,
			Source: "cryptex-system-arm64e",
			Err: errors.New("failed to mount /var/folders/9k/T/ota_extract_cryptexes123/" +
				"cryptex-system-arm64e.dmg: hdiutil: attach failed - Resource busy"),
		},
		&ota.PhaseError{
			Phase:  ota.PhaseCleanup,
			Source: "cryptex-system-rosetta",
			Err: errors.New("failed to unmount /tmp/cryptex-system-rosetta.dmg.mount: " +
				"hdiutil: detach failed - Resource busy"),
		},
	))
	assertReport(t, rep.finish(), wantPartialSuccessReport)
}

const wantTotalFailureReport = `{"schema_version":1,"complete":false,"files":[],"errors":[{"phase":"payload-extract","source":"payload.042","message":"payload.042: payload-extract: exec: \"aa\": executable file not found in $PATH"},{"phase":"dsc-discovery","source":"","message":"no dyld_shared_cache files were materialized from any OTA source (cryptexes, asset files, payloadv2)"}]}`

func TestWriteDSCReportTotalFailure(t *testing.T) {
	src := &fakeDSCSource{
		cryptexErr: ota.ErrNoDscInCryptexes,
		payloadErr: &ota.PhaseError{
			Phase:  ota.PhasePayloadExtract,
			Source: "payload.042",
			Err:    errors.New(`exec: "aa": executable file not found in $PATH`),
		},
	}
	assertReport(t, extractDSC(src, testOpts()), wantTotalFailureReport)
}

func assertReport(t *testing.T, rep *dscReport, want string) {
	t.Helper()
	var buf bytes.Buffer
	if err := writeDSCReport(&buf, rep); err != nil {
		t.Fatalf("writeDSCReport() unexpected error: %v", err)
	}
	got := buf.String()
	if !strings.HasSuffix(got, "\n") || strings.Count(got, "\n") != 1 {
		t.Fatalf("writeDSCReport() output = %q, want exactly one trailing newline", got)
	}
	line := strings.TrimSuffix(got, "\n")
	if !json.Valid([]byte(line)) {
		t.Fatalf("writeDSCReport() output is not valid JSON: %q", line)
	}
	if line != want {
		t.Fatalf("writeDSCReport() =\n%s\nwant\n%s", line, want)
	}
	for _, key := range []string{`"path":`, `"arch":`, `"source":`} {
		if strings.Contains(line, `"files":[{`) && !strings.Contains(line, key) {
			t.Errorf("writeDSCReport() output is missing always-present key %s", key)
		}
	}
	if strings.Contains(line, "null") {
		t.Errorf("writeDSCReport() output contains null: %q", line)
	}
}

func TestWriteDSCReportEmptyArraysAreNeverNull(t *testing.T) {
	var buf bytes.Buffer
	if err := writeDSCReport(&buf, newDSCReport().finish()); err != nil {
		t.Fatalf("writeDSCReport() unexpected error: %v", err)
	}
	want := `{"schema_version":1,"complete":true,"files":[],"errors":[]}` + "\n"
	if buf.String() != want {
		t.Fatalf("writeDSCReport() = %q, want %q", buf.String(), want)
	}
}

func TestFailedDSCReportPromotesPhase(t *testing.T) {
	err := fmt.Errorf("failed to open OTA file: %w", &ota.PhaseError{
		Phase: ota.PhaseAEADecrypt,
		Err:   errors.New("no key found"),
	})
	rep := failedDSCReport(ota.PhaseOTAOpen, err)

	if rep.Complete {
		t.Fatal("report.Complete = true, want false")
	}
	if len(rep.Errors) != 1 {
		t.Fatalf("report.Errors = %+v, want 1 entry", rep.Errors)
	}
	if rep.Errors[0].Phase != ota.PhaseAEADecrypt {
		t.Errorf("error phase = %q, want %q", rep.Errors[0].Phase, ota.PhaseAEADecrypt)
	}
}

func TestDSCReportPath(t *testing.T) {
	tests := []struct {
		name string
		root string
		dst  string
		want string
	}{
		{
			name: "no --output",
			root: ".",
			dst:  "24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e",
			want: "24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e",
		},
		{
			name: "absolute --output",
			root: "/tmp/out",
			dst:  "/tmp/out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e",
			want: "24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e",
		},
		{
			name: "relative --output",
			root: "out",
			dst:  "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e",
			want: "24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e",
		},
		{
			// info.GetFolder builds this from the MobileAsset type, not from a
			// device list, so it has no double underscore. Pinned by
			// pkg/info.TestGetFolderSimulatorRuntimeUsesAssetType.
			name: "simulator runtime folder",
			root: ".",
			dst:  "18.2_22C150_iOSSimulatorRuntime/System/Library/dyld/dyld_shared_cache_arm64e",
			want: "18.2_22C150_iOSSimulatorRuntime/System/Library/dyld/dyld_shared_cache_arm64e",
		},
		{
			name: "unrelatable base keeps the file in the report",
			root: "/tmp/out",
			dst:  "relative/24G720__MacOS/dyld_shared_cache_arm64e",
			want: "relative/24G720__MacOS/dyld_shared_cache_arm64e",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dscReportPath(tt.root, tt.dst); got != tt.want {
				t.Fatalf("dscReportPath(%q, %q) = %q, want %q", tt.root, tt.dst, got, tt.want)
			}
		})
	}
}

func TestDSCArch(t *testing.T) {
	tests := []struct{ path, want string }{
		{"System/Library/dyld/dyld_shared_cache_arm64e", "arm64e"},
		{"System/Library/dyld/dyld_shared_cache_arm64e.01", "arm64e"},
		{"System/Library/dyld/dyld_shared_cache_arm64e.symbols", "arm64e"},
		{"System/Library/dyld/dyld_shared_cache_arm64e.dylddata", "arm64e"},
		{"System/Library/dyld/dyld_shared_cache_arm64e.map", "arm64e"},
		{"dyld_shared_cache_arm64", "arm64"},
		{"dyld_shared_cache_x86_64", "x86_64"},
		{"dyld_shared_cache_x86_64h", "x86_64h"},
		{"dyld_shared_cache_arm64_32", "arm64_32"},
		{"System/Library/dyld/aot_shared_cache.0", "aot"},
		{"System/Library/dyld/aot_shared_cache.12", "aot"},
		{"aot_shared_cache", ""},
		{"dyld_shared_cache_", ""},
		{"kernelcache", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := dscArch(tt.path); got != tt.want {
				t.Fatalf("dscArch(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestDSCPatternForArches(t *testing.T) {
	tests := []struct {
		name    string
		arches  []string
		matches []string
		rejects []string
	}{
		{
			name:   "arm64 is exact",
			arches: []string{"arm64"},
			matches: []string{
				"System/Library/dyld/dyld_shared_cache_arm64",
				"System/Library/dyld/dyld_shared_cache_arm64.01",
			},
			rejects: []string{"System/Library/dyld/dyld_shared_cache_arm64e"},
		},
		{
			name:   "arm64_32 is supported",
			arches: []string{"arm64_32"},
			matches: []string{
				"System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64_32",
			},
			rejects: []string{"System/Library/dyld/dyld_shared_cache_arm64"},
		},
		{
			name:   "aot does not select x86 caches",
			arches: []string{"aot"},
			matches: []string{
				"System/Library/dyld/aot_shared_cache.0",
			},
			rejects: []string{
				"System/Library/dyld/dyld_shared_cache_x86_64",
				"System/Library/dyld/aot_shared_cache.foo",
			},
		},
		{
			name:   "multiple families",
			arches: []string{"arm64e", "x86_64h"},
			matches: []string{
				"System/DriverKit/System/Library/dyld/dyld_shared_cache_arm64e.symbols",
				"System/x86Support/System/Library/dyld/dyld_shared_cache_x86_64h",
			},
			rejects: []string{"System/Library/dyld/aot_shared_cache.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re := dscPatternForArches(tt.arches)
			for _, path := range tt.matches {
				if !matchesPostBOMPattern(re, path) {
					t.Errorf("pattern %q does not match %q", re, path)
				}
			}
			for _, path := range tt.rejects {
				if matchesPostBOMPattern(re, path) {
					t.Errorf("pattern %q unexpectedly matches %q", re, path)
				}
			}
		})
	}
}

func TestDSCUberRegexMatchesKnownCachePaths(t *testing.T) {
	paths := []string{
		"System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
		"System/DriverKit/System/Library/dyld/dyld_shared_cache_arm64e",
		"System/Library/dyld/aot_shared_cache.0",
		"System/Library/dyld/aot_shared_cache.6",
		"System/Library/dyld/dyld_shared_cache_x86_64",
	}
	for _, path := range paths {
		if !matchesPostBOMPattern(reDSCUber, path) {
			t.Errorf("reDSCUber does not match full path %q", path)
		}
	}

	falsePositives := []string{
		"System/Library/dyld/aot_shared_cache",
		"System/Library/dyld/aot_shared_cache.foo",
		"System/Library/dyld/aot_shared_cache.0.map",
		"System/Library/Caches/com.apple.dyld/aot_shared_cache.0",
		"usr/lib/aot_shared_cache.0",
	}
	for _, path := range falsePositives {
		if matchesPostBOMPattern(reDSCUber, path) {
			t.Errorf("reDSCUber unexpectedly matches full path %q", path)
		}
	}
}

func TestFlattenErrors(t *testing.T) {
	a := errors.New("a")
	b := errors.New("b")
	c := errors.New("c")

	if got := flattenErrors(nil); got != nil {
		t.Errorf("flattenErrors(nil) = %v, want nil", got)
	}
	if got := flattenErrors(a); len(got) != 1 {
		t.Errorf("flattenErrors(plain) = %v, want 1 entry", got)
	}
	if got := flattenErrors(errors.Join(a, b)); len(got) != 2 {
		t.Errorf("flattenErrors(join) = %v, want 2 entries", got)
	}
	if got := flattenErrors(errors.Join(a, errors.Join(b, c))); len(got) != 3 {
		t.Errorf("flattenErrors(nested join) = %v, want 3 entries", got)
	}
	phase := &ota.PhaseError{Phase: ota.PhaseMount, Err: errors.Join(a, b)}
	if got := flattenErrors(phase); len(got) != 1 {
		t.Errorf("flattenErrors(*PhaseError) = %v, want 1 leaf entry", got)
	}
}

func TestRunDyldExtractPromptSelection(t *testing.T) {
	tests := []struct {
		name       string
		json       bool
		confirm    bool
		wantPrompt bool
	}{
		{name: "interactive", wantPrompt: true},
		{name: "json only", json: true},
		{name: "confirm only", confirm: true},
		{name: "json and confirm", json: true, confirm: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prompt := dscPrompt(otaExtractFlags{json: tt.json, confirm: tt.confirm})
			if got := prompt != nil; got != tt.wantPrompt {
				t.Fatalf("dscPrompt() non-nil = %v, want %v", got, tt.wantPrompt)
			}
		})
	}
}

// TestExtractDSCPayloadPartialFailureIsIncomplete pins the exact sequence the
// differential review flagged: one payload member fails while another yields a
// cache. The materialized file must survive AND the failure must reach the
// report, so `complete` cannot claim success over a lost source failure.
func TestExtractDSCPayloadPartialFailureIsIncomplete(t *testing.T) {
	src := &fakeDSCSource{
		cryptexErr: ota.ErrNoDscInCryptexes,
		payload:    []string{"out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e"},
		payloadErr: &ota.PhaseError{
			Phase:  ota.PhasePayloadExtract,
			Source: "payload.001",
			Err:    errors.New("aa extract failed: exit status 1"),
		},
	}

	rep := extractDSC(src, testOpts())

	if len(rep.Files) != 1 {
		t.Fatalf("report.Files = %+v, want the one recovered cache retained", rep.Files)
	}
	if rep.Complete {
		t.Error("report.Complete = true despite a failed payload member")
	}
	if len(rep.Errors) != 1 {
		t.Fatalf("report.Errors = %+v, want exactly the payload failure", rep.Errors)
	}
	if got := rep.Errors[0]; got.Phase != ota.PhasePayloadExtract || got.Source != "payload.001" {
		t.Errorf("error = {phase:%q source:%q}, want {payload-extract payload.001}", got.Phase, got.Source)
	}
	if rep.fatalErr() == nil {
		t.Error("fatalErr() = nil; a real source failure must drive a non-zero exit")
	}
}

// TestExtractDSCKeepsPriorFileWhenAssetCopyFailsBeforeWriting pins that a
// fallback asset copy which fails BEFORE touching the destination (e.g. the OTA
// member cannot be opened) leaves an earlier source's entry in place. Only a
// mid-write failure destroys the file; dropping the row unconditionally would
// hide a materialized cache and could make missingArches claim its arch absent.
func TestExtractDSCKeepsPriorFileWhenAssetCopyFailsBeforeWriting(t *testing.T) {
	out := t.TempDir()
	survivor := filepath.Join(out, "24G720__MacOS", "System", "Library", "dyld", "dyld_shared_cache_arm64e")
	if err := os.MkdirAll(filepath.Dir(survivor), 0o755); err != nil {
		t.Fatal(err)
	}
	// The cryptex already materialized this file and it is still on disk.
	if err := os.WriteFile(survivor, []byte("cache"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := &fakeDSCSource{
		cryptexFiles: []ota.ExtractedFile{{Path: survivor, Source: "cryptex-system-arm64e"}},
		cryptexErr: &ota.PhaseError{
			Phase:  ota.PhaseMount,
			Source: "cryptex-system-x86_64h",
			Err:    errors.New("hdiutil: attach failed"),
		},
		assets: []string{"System/Library/dyld/dyld_shared_cache_arm64e"},
		// Fails before opening/truncating the destination.
		copyErr: errors.New("failed to open file in OTA: unexpected EOF"),
	}

	rep := extractDSC(src, dscOptions{Output: filepath.Join(out, "24G720__MacOS"), ReportRoot: out})

	want := "24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e"
	if !slices.ContainsFunc(rep.Files, func(f dscFileEntry) bool { return f.Path == want }) {
		t.Errorf("report.Files = %+v; dropped %q even though the file is still on disk", rep.Files, want)
	}
	if _, err := os.Stat(survivor); err != nil {
		t.Fatalf("precondition broken: survivor file vanished: %v", err)
	}
	if rep.Complete {
		t.Error("report.Complete = true despite the failed asset copy")
	}
}
