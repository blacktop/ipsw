package ota

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestCopyMatchesFromMountKeepsCopyPhase pins that a copy failure inside a
// mounted cryptex is reported as `copy`, not as the walk's `dsc-discovery`
// default. Callers key retry decisions off the phase and must never have to
// pattern-match the free-form message.
func TestCopyMatchesFromMountKeepsCopyPhase(t *testing.T) {
	mount := t.TempDir()
	dsc := filepath.Join(mount, "System", "Library", "dyld")
	if err := os.MkdirAll(dsc, 0o750); err != nil {
		t.Fatalf("failed to seed mount point: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dsc, "dyld_shared_cache_arm64e"), []byte("dsc"), 0o644); err != nil {
		t.Fatalf("failed to seed mount point: %v", err)
	}
	// A regular file where the output tree needs a directory makes the copy,
	// and only the copy, fail.
	output := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(output, nil, 0o644); err != nil {
		t.Fatalf("failed to seed output: %v", err)
	}

	file := &File{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64e"}
	_, err := copyMatchesFromMount(file, regexp.MustCompile(`dyld_shared_cache_arm64e$`), mount, output)
	if err == nil {
		t.Fatal("copyMatchesFromMount() error = nil, want a copy failure")
	}

	var pe *PhaseError
	if !errors.As(err, &pe) {
		t.Fatalf("copyMatchesFromMount() error = %v, want a *PhaseError", err)
	}
	if pe.Phase != PhaseCopy {
		t.Errorf("PhaseError.Phase = %q, want %q", pe.Phase, PhaseCopy)
	}
	if pe.Source != "cryptex-system-arm64e" {
		t.Errorf("PhaseError.Source = %q, want %q", pe.Source, "cryptex-system-arm64e")
	}
}

func TestCopyMatchesFromMountCopiesMatches(t *testing.T) {
	mount := t.TempDir()
	dsc := filepath.Join(mount, "System", "Library", "dyld")
	if err := os.MkdirAll(dsc, 0o750); err != nil {
		t.Fatalf("failed to seed mount point: %v", err)
	}
	for _, name := range []string{"dyld_shared_cache_arm64e", "dyld_shared_cache_arm64e.01", "kernelcache"} {
		if err := os.WriteFile(filepath.Join(dsc, name), []byte(name), 0o644); err != nil {
			t.Fatalf("failed to seed mount point: %v", err)
		}
	}
	output := t.TempDir()

	file := &File{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64e"}
	out, err := copyMatchesFromMount(file, regexp.MustCompile(`dyld_shared_cache_arm64e`), mount, output)
	if err != nil {
		t.Fatalf("copyMatchesFromMount() unexpected error: %v", err)
	}
	want := []string{
		filepath.Join(output, "System/Library/dyld/dyld_shared_cache_arm64e"),
		filepath.Join(output, "System/Library/dyld/dyld_shared_cache_arm64e.01"),
	}
	if !slices.Equal(out, want) {
		t.Fatalf("copied files = %v, want %v", out, want)
	}
	for _, path := range want {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("copied file %q is missing: %v", path, err)
		}
	}
}

func TestExtractFromDscCryptexFilesIncludesRosettaAndContinuesAfterFailure(t *testing.T) {
	files := []*File{
		{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64e"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-rosetta"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-x86_64h"},
		{name: "AssetData/payloadv2/image_patches/cryptex-app"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-rosetta.dmg"},
		{name: "AssetData/payloadv2/image_patches/prefix-cryptex-system-rosetta"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-rosetta-extra"},
	}

	var called []string
	out, err := extractFromDscCryptexFiles(files, func(file *File) ([]string, error) {
		called = append(called, file.Base())
		switch file.Base() {
		case "cryptex-system-arm64e":
			return nil, errors.New("hdiutil attach: Device not configured")
		case "cryptex-system-rosetta":
			return []string{
				"System/Library/dyld/aot_shared_cache.0",
				"System/Library/dyld/dyld_shared_cache_x86_64",
			}, nil
		case "cryptex-system-x86_64h":
			return []string{"System/Library/dyld/dyld_shared_cache_x86_64h"}, nil
		default:
			t.Fatalf("unexpected cryptex extraction attempt for %q", file.Name())
			return nil, nil
		}
	})

	wantCalled := []string{
		"cryptex-system-arm64e",
		"cryptex-system-rosetta",
		"cryptex-system-x86_64h",
	}
	if !slices.Equal(called, wantCalled) {
		t.Fatalf("extract calls = %v, want %v", called, wantCalled)
	}
	wantOut := []ExtractedFile{
		{Path: "System/Library/dyld/aot_shared_cache.0", Source: "cryptex-system-rosetta"},
		{Path: "System/Library/dyld/dyld_shared_cache_x86_64", Source: "cryptex-system-rosetta"},
		{Path: "System/Library/dyld/dyld_shared_cache_x86_64h", Source: "cryptex-system-x86_64h"},
	}
	if !slices.Equal(out, wantOut) {
		t.Fatalf("extracted files = %v, want %v", out, wantOut)
	}
	if err == nil {
		t.Fatal("extractFromDscCryptexFiles() error = nil, want arm64e extraction error")
	}
	for _, want := range []string{"cryptex-system-arm64e", "Device not configured"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("extractFromDscCryptexFiles() error = %q, want substring %q", err, want)
		}
	}
}

func TestExtractFromDscCryptexFilesReturnsNilErrorWhenAllCryptexesSucceed(t *testing.T) {
	files := []*File{
		{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-rosetta"},
	}

	out, err := extractFromDscCryptexFiles(files, func(file *File) ([]string, error) {
		return []string{file.Base()}, nil
	})
	if err != nil {
		t.Fatalf("extractFromDscCryptexFiles() unexpected error: %v", err)
	}
	want := []ExtractedFile{
		{Path: "cryptex-system-arm64", Source: "cryptex-system-arm64"},
		{Path: "cryptex-system-rosetta", Source: "cryptex-system-rosetta"},
	}
	if !slices.Equal(out, want) {
		t.Fatalf("extracted files = %v, want %v", out, want)
	}
}

func TestExtractFromDscCryptexFilesForArchesSearchesContentsInsteadOfBasenames(t *testing.T) {
	files := []*File{
		{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64e"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-x86_64"},
	}
	var called []string
	out, err := extractFromDscCryptexFilesForArches(files, []string{"x86_64"}, func(file *File) ([]string, error) {
		called = append(called, file.Base())
		if file.Base() != "cryptex-system-arm64e" {
			t.Fatalf("extraction continued with %q after x86_64 was already materialized", file.Base())
		}
		return []string{"out/System/Library/dyld/dyld_shared_cache_x86_64"}, nil
	})
	if err != nil {
		t.Fatalf("extractFromDscCryptexFilesForArches() unexpected error: %v", err)
	}
	if want := []string{"cryptex-system-arm64e"}; !slices.Equal(called, want) {
		t.Fatalf("extracted cryptexes = %v, want %v", called, want)
	}
	want := []ExtractedFile{{
		Path:   "out/System/Library/dyld/dyld_shared_cache_x86_64",
		Source: "cryptex-system-arm64e",
	}}
	if !slices.Equal(out, want) {
		t.Fatalf("output = %+v, want %+v", out, want)
	}
}

func TestExtractFromDscCryptexFilesForArchesDoesNotStopOnPartialFailure(t *testing.T) {
	files := []*File{
		{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64e"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-x86_64"},
	}
	var called []string
	out, err := extractFromDscCryptexFilesForArches(files, []string{"x86_64"}, func(file *File) ([]string, error) {
		called = append(called, file.Base())
		path := "out/System/Library/dyld/dyld_shared_cache_x86_64"
		if file.Base() == "cryptex-system-arm64e" {
			return []string{path}, errors.New("copy failed after a partial result")
		}
		return []string{path}, nil
	})
	if err == nil {
		t.Fatal("extractFromDscCryptexFilesForArches() error = nil, want the partial failure preserved")
	}
	wantCalled := []string{"cryptex-system-arm64e", "cryptex-system-x86_64"}
	if !slices.Equal(called, wantCalled) {
		t.Fatalf("extracted cryptexes = %v, want %v", called, wantCalled)
	}
	if len(out) != 2 {
		t.Fatalf("output = %+v, want both partial and later successful results", out)
	}
}

func TestExtractFromDscCryptexFilesForArchesSearchesEveryCandidateWhenAbsent(t *testing.T) {
	files := []*File{
		{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64e"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64_32"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-x86_64"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-x86_64h"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-rosetta"},
		{name: "AssetData/payloadv2/image_patches/cryptex-app"},
	}
	var called []string
	out, err := extractFromDscCryptexFilesForArches(files, []string{"x86_64"}, func(file *File) ([]string, error) {
		called = append(called, file.Base())
		return nil, nil
	})
	if err != nil {
		t.Fatalf("extractFromDscCryptexFilesForArches() unexpected error: %v", err)
	}
	want := []string{
		"cryptex-system-arm64",
		"cryptex-system-arm64e",
		"cryptex-system-arm64_32",
		"cryptex-system-x86_64",
		"cryptex-system-x86_64h",
		"cryptex-system-rosetta",
	}
	if !slices.Equal(called, want) {
		t.Fatalf("extracted cryptexes = %v, want exhaustive search of %v", called, want)
	}
	if out != nil {
		t.Fatalf("output = %+v, want nil", out)
	}
}

func TestDscPathMatchesArch(t *testing.T) {
	tests := []struct {
		name string
		path string
		arch string
		want bool
	}{
		{name: "primary", path: "out/System/Library/dyld/dyld_shared_cache_arm64", arch: "arm64", want: true},
		{name: "subcache", path: "out/System/Library/dyld/dyld_shared_cache_x86_64.06", arch: "x86_64", want: true},
		{name: "symbols", path: "out/System/Library/dyld/dyld_shared_cache_arm64e.symbols", arch: "arm64e", want: true},
		{name: "architecture boundary", path: "out/System/Library/dyld/dyld_shared_cache_arm64e", arch: "arm64"},
		{name: "aot", path: "out/System/Library/dyld/aot_shared_cache.0", arch: "aot", want: true},
		{name: "not aot", path: "out/System/Library/dyld/dyld_shared_cache_x86_64", arch: "aot"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dscPathMatchesArch(tt.path, tt.arch); got != tt.want {
				t.Fatalf("dscPathMatchesArch(%q, %q) = %t, want %t", tt.path, tt.arch, got, tt.want)
			}
		})
	}
}

func TestExtractFromDscCryptexFilesTagsSource(t *testing.T) {
	files := []*File{{name: "AssetData/payloadv2/image_patches/cryptex-system-rosetta"}}

	out, err := extractFromDscCryptexFiles(files, func(file *File) ([]string, error) {
		return []string{
			"out/System/Library/dyld/aot_shared_cache.0",
			"out/System/Library/dyld/dyld_shared_cache_x86_64",
		}, nil
	})
	if err != nil {
		t.Fatalf("extractFromDscCryptexFiles() unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("extracted files = %v, want 2 entries", out)
	}
	for _, got := range out {
		if got.Source != "cryptex-system-rosetta" {
			t.Errorf("ExtractedFile(%q).Source = %q, want %q", got.Path, got.Source, "cryptex-system-rosetta")
		}
	}
}

func TestExtractFromDscCryptexFilesKeepsFilesFromPartiallyFailingCryptex(t *testing.T) {
	files := []*File{{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64e"}}

	out, err := extractFromDscCryptexFiles(files, func(file *File) ([]string, error) {
		return []string{"out/System/Library/dyld/dyld_shared_cache_arm64e"},
			errors.New("failed to unmount")
	})
	if err == nil {
		t.Fatal("extractFromDscCryptexFiles() error = nil, want unmount error")
	}
	want := []ExtractedFile{{
		Path:   "out/System/Library/dyld/dyld_shared_cache_arm64e",
		Source: "cryptex-system-arm64e",
	}}
	if !slices.Equal(out, want) {
		t.Fatalf("extracted files = %v, want %v", out, want)
	}
}

func TestExtractFromDscCryptexFilesAttributesPhase(t *testing.T) {
	files := []*File{{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64e"}}

	_, err := extractFromDscCryptexFiles(files, func(file *File) ([]string, error) {
		return nil, &PhaseError{
			Phase:  PhaseMount,
			Source: file.Base(),
			Err:    errors.New("hdiutil: attach failed - Resource busy"),
		}
	})
	if err == nil {
		t.Fatal("extractFromDscCryptexFiles() error = nil, want mount error")
	}
	var pe *PhaseError
	if !errors.As(err, &pe) {
		t.Fatalf("extractFromDscCryptexFiles() error = %v, want *PhaseError", err)
	}
	if pe.Phase != PhaseMount {
		t.Errorf("PhaseError.Phase = %q, want %q", pe.Phase, PhaseMount)
	}
	if pe.Source != "cryptex-system-arm64e" {
		t.Errorf("PhaseError.Source = %q, want %q", pe.Source, "cryptex-system-arm64e")
	}
}

func TestPhaseErrorUnwrapPreservesCryptexNotFound(t *testing.T) {
	err := &PhaseError{
		Phase:  PhaseCryptexDiscovery,
		Source: "cryptex-app",
		Err:    fmt.Errorf("%w: 'app'", ErrCryptexNotFound),
	}
	if !errors.Is(err, ErrCryptexNotFound) {
		t.Fatalf("errors.Is(%v, ErrCryptexNotFound) = false, want true", err)
	}
	if want := "cryptex-app: cryptex-discovery: cryptex not found: 'app'"; err.Error() != want {
		t.Fatalf("PhaseError.Error() = %q, want %q", err.Error(), want)
	}
}

func TestWrapPhaseLeavesClassifiedErrorsAlone(t *testing.T) {
	if got := wrapPhase(PhaseCopy, "x", nil); got != nil {
		t.Fatalf("wrapPhase(_, _, nil) = %v, want nil", got)
	}

	inner := &PhaseError{Phase: PhaseMount, Source: "cryptex-system-arm64e", Err: errors.New("boom")}
	if got := wrapPhase(PhaseCryptexDiscovery, "other", inner); got != error(inner) {
		t.Fatalf("wrapPhase() = %v, want the original classified error", got)
	}

	plain := errors.New("boom")
	got := wrapPhase(PhaseCryptexDiscovery, "cryptex-system-arm64e", plain)
	var pe *PhaseError
	if !errors.As(got, &pe) {
		t.Fatalf("wrapPhase() = %v, want *PhaseError", got)
	}
	if pe.Phase != PhaseCryptexDiscovery || pe.Source != "cryptex-system-arm64e" {
		t.Fatalf("wrapPhase() = %+v, want phase=%q source=%q", pe, PhaseCryptexDiscovery, "cryptex-system-arm64e")
	}
	if !errors.Is(got, plain) {
		t.Fatal("wrapPhase() lost the wrapped error")
	}
}

// TestPhaseErrorErrorOmitsPhaseWithoutSource pins that an unattributable
// failure renders exactly as its cause, so human output gains no noise from
// the machine-readable phase tag.
func TestPhaseErrorErrorOmitsPhaseWithoutSource(t *testing.T) {
	err := &PhaseError{Phase: PhaseAEADecrypt, Err: errors.New("failed to decrypt AEA: no key found")}
	if want := "failed to decrypt AEA: no key found"; err.Error() != want {
		t.Fatalf("PhaseError.Error() = %q, want %q", err.Error(), want)
	}
}

// TestGetPayloadFilesRejectsMalformedRangeWithoutPanicking pins that a bad
// payloadRange is returned as a phase-attributed error. It reaches
// regexp.MustCompile otherwise, which panics on user-supplied --range input.
func TestGetPayloadFilesRejectsMalformedRangeWithoutPanicking(t *testing.T) {
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("GetPayloadFiles panicked on a malformed range: %v", p)
		}
	}()

	r := &Reader{}
	err := r.GetPayloadFiles(".*", "[", t.TempDir())
	if err == nil {
		t.Fatal("GetPayloadFiles(malformed range) = nil, want an error")
	}

	var pe *PhaseError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a *PhaseError, so callers cannot classify it", err)
	}
	if pe.Phase != PhasePayloadExtract {
		t.Errorf("phase = %q, want %q", pe.Phase, PhasePayloadExtract)
	}
}

// TestExtractFromCryptexesKeepsPartialPathsOnError pins the load-bearing half
// of the restored []string API. ExtractFromCryptexes is
// extractedPaths(ExtractFromCryptexesWithSources(...)), so a cryptex that fails
// after another already wrote caches to disk must still hand those paths back
// to the caller; an `if err != nil { return nil, err }` wrapper would silently
// discard files that exist and are valid.
func TestExtractFromCryptexesKeepsPartialPathsOnError(t *testing.T) {
	files := []*File{
		{name: "AssetData/payloadv2/image_patches/cryptex-system-rosetta"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64e"},
	}
	// One cryptex materializes caches and the next one fails: exactly the pair
	// ExtractFromCryptexesWithSources hands the wrapper.
	out, err := extractFromDscCryptexFiles(files, func(file *File) ([]string, error) {
		if file.Base() == "cryptex-system-arm64e" {
			return nil, errors.New("hdiutil: attach failed - Resource busy")
		}
		return []string{
			"out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_x86_64",
			"out/24G720__MacOS/System/Library/dyld/aot_shared_cache.0",
		}, nil
	})
	if err == nil {
		t.Fatal("extractFromDscCryptexFiles() error = nil, want the arm64e mount failure")
	}

	paths, gotErr := extractedPaths(out, err)
	if gotErr == nil {
		t.Fatal("extractedPaths() error = nil, want the mount failure preserved")
	}
	want := []string{
		"out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_x86_64",
		"out/24G720__MacOS/System/Library/dyld/aot_shared_cache.0",
	}
	if !slices.Equal(paths, want) {
		t.Fatalf("paths = %v, want %v returned alongside the error", paths, want)
	}
}

// TestExtractedPathsReturnsNilForEmptyResults pins that an empty result stays a
// nil slice, as it was before the wrapper existed, so a downstream `== nil`
// check keeps working.
func TestExtractedPathsReturnsNilForEmptyResults(t *testing.T) {
	boom := errors.New("boom")
	if paths, err := extractedPaths(nil, boom); paths != nil || !errors.Is(err, boom) {
		t.Errorf("extractedPaths(nil, boom) = (%v, %v), want (nil, boom)", paths, err)
	}
	if paths, err := extractedPaths(nil, nil); paths != nil || err != nil {
		t.Errorf("extractedPaths(nil, nil) = (%v, %v), want (nil, nil)", paths, err)
	}
}

// TestExtractFromCryptexesPreservesErrNoDscInCryptexes pins that neither
// exported variant flattens the sentinel. The --dyld report keys "this source
// does not apply" off errors.Is, so a delta OTA would otherwise be recorded as
// a hard failure and mark every report incomplete.
func TestExtractFromCryptexesPreservesErrNoDscInCryptexes(t *testing.T) {
	output := t.TempDir()

	// An OTA carrying no cryptex members at all.
	paths, err := (&Reader{}).ExtractFromCryptexes(`dyld_shared_cache_`, output)
	if !errors.Is(err, ErrNoDscInCryptexes) {
		t.Fatalf("ExtractFromCryptexes() error = %v, want ErrNoDscInCryptexes", err)
	}
	if paths != nil {
		t.Errorf("ExtractFromCryptexes() paths = %v, want nil", paths)
	}

	files, err := (&Reader{}).ExtractFromCryptexesWithSources(`dyld_shared_cache_`, output)
	if !errors.Is(err, ErrNoDscInCryptexes) {
		t.Fatalf("ExtractFromCryptexesWithSources() error = %v, want ErrNoDscInCryptexes", err)
	}
	if files != nil {
		t.Errorf("ExtractFromCryptexesWithSources() files = %v, want nil", files)
	}
}

// newUnreadablePayloadReader returns a Reader holding one payloadv2 member that
// Reader.Open rejects. The leading slash fails fs.ValidPath before Open reaches
// the archive entry, which is what makes a per-member failure reachable without
// a real OTA.
func newUnreadablePayloadReader(t *testing.T) *Reader {
	t.Helper()
	r := &Reader{}
	r.initFileList() // consume the sync.Once so the seeded list survives
	r.fileList = []*File{{name: "/AssetData/payloadv2/payload.001"}}
	return r
}

// TestGetPayloadFilesMatchesNilCallbackVariant pins that the restored 3-arg
// method is a pure delegation rather than a second implementation that can
// drift from the callback variant.
func TestGetPayloadFilesMatchesNilCallbackVariant(t *testing.T) {
	t.Run("per-member failure", func(t *testing.T) {
		plain := newUnreadablePayloadReader(t).GetPayloadFiles(".*", "", t.TempDir())
		withCallback := newUnreadablePayloadReader(t).
			GetPayloadFilesWithCallback(".*", "", t.TempDir(), nil)
		if plain == nil || withCallback == nil {
			t.Fatalf("errors = (%v, %v), want both non-nil", plain, withCallback)
		}
		if plain.Error() != withCallback.Error() {
			t.Fatalf("GetPayloadFiles() = %q, GetPayloadFilesWithCallback(nil) = %q, want identical",
				plain, withCallback)
		}
		var pe *PhaseError
		if !errors.As(plain, &pe) {
			t.Fatalf("error %v is not a *PhaseError, so callers cannot classify it", plain)
		}
		if pe.Phase != PhasePayloadExtract || pe.Source != "payload.001" {
			t.Errorf("error attributed to %q/%q, want %q/%q", pe.Source, pe.Phase, "payload.001", PhasePayloadExtract)
		}
	})

	t.Run("no matching members", func(t *testing.T) {
		if err := (&Reader{}).GetPayloadFiles(".*", "", t.TempDir()); err != nil {
			t.Errorf("GetPayloadFiles() = %v, want nil", err)
		}
		if err := (&Reader{}).GetPayloadFilesWithCallback(".*", "", t.TempDir(), nil); err != nil {
			t.Errorf("GetPayloadFilesWithCallback(nil) = %v, want nil", err)
		}
	})

	t.Run("malformed range", func(t *testing.T) {
		plain := (&Reader{}).GetPayloadFiles(".*", "[", t.TempDir())
		withCallback := (&Reader{}).GetPayloadFilesWithCallback(".*", "[", t.TempDir(), nil)
		if plain == nil || withCallback == nil {
			t.Fatalf("errors = (%v, %v), want both non-nil", plain, withCallback)
		}
		if plain.Error() != withCallback.Error() {
			t.Fatalf("GetPayloadFiles() = %q, GetPayloadFilesWithCallback(nil) = %q, want identical",
				plain, withCallback)
		}
	})
}

// TestAAExtractPatternPropagatesNonZeroExit pins that a failing `aa` is an
// error. It exits 0 when the regex simply matches nothing, so suppressing
// non-zero status would let a failed payload member vanish from the report
// while `complete` still claimed success.
func TestAAExtractPatternPropagatesNonZeroExit(t *testing.T) {
	if _, err := exec.LookPath("aa"); err != nil {
		t.Skip("aa not available")
	}
	out := t.TempDir()

	// A non-archive stream makes aa exit non-zero.
	if err := aaExtractPattern(strings.NewReader("definitely not an apple archive"), ".*", out); err == nil {
		t.Fatal("aaExtractPattern(non-archive) = nil, want an error")
	}

	// An invalid regex also exits non-zero.
	if err := aaExtractPattern(strings.NewReader("x"), "[", out); err == nil {
		t.Fatal("aaExtractPattern(invalid regex) = nil, want an error")
	}
}

// TestCopyMatchesFromMountReportsWalkErrors pins that an unreadable subtree is
// reported rather than silently skipped: an untraversed directory is not proof
// that it held no caches, so it must not leave the report claiming complete.
func TestCopyMatchesFromMountReportsWalkErrors(t *testing.T) {
	root := t.TempDir()
	readable := filepath.Join(root, "System", "Library", "dyld")
	if err := os.MkdirAll(readable, 0o755); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(readable, "dyld_shared_cache_arm64e")
	if err := os.WriteFile(cache, []byte("cache"), 0o644); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(root, "blocked")
	if err := os.MkdirAll(filepath.Join(blocked, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
	if os.Geteuid() == 0 {
		t.Skip("running as root defeats the unreadable-directory setup")
	}

	out, err := copyMatchesFromMount(
		&File{name: "cryptex-system-arm64e"},
		regexp.MustCompile(`dyld_shared_cache_`),
		root,
		t.TempDir(),
	)

	if len(out) != 1 {
		t.Errorf("copied %v, want the one readable cache retained alongside the error", out)
	}
	if err == nil {
		t.Fatal("err = nil, want the unreadable subtree reported")
	}
	var pe *PhaseError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a *PhaseError, so it cannot be classified in the report", err)
	}
	if pe.Source != "cryptex-system-arm64e" {
		t.Errorf("source = %q, want the cryptex member", pe.Source)
	}
}

// TestJoinRemoveTempDirReportsFailure pins that a temp dir which cannot be
// removed becomes a PhaseCleanup error even when extraction itself succeeded.
// Without this, a run can materialize every file, leak its temp dir, and still
// report complete.
func TestJoinRemoveTempDirReportsFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can unlink from a read-only directory")
	}
	parent := t.TempDir()
	victim := filepath.Join(parent, "leaked")
	if err := os.MkdirAll(filepath.Join(victim, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Removal needs write permission on the PARENT to unlink the entry.
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

	t.Run("surfaces on an otherwise successful run", func(t *testing.T) {
		err := joinRemoveTempDir(nil, "payload.004", victim)
		if err == nil {
			t.Fatal("joinRemoveTempDir(nil, ...) = nil, want the leak reported")
		}
		var pe *PhaseError
		if !errors.As(err, &pe) {
			t.Fatalf("error %v is not a *PhaseError", err)
		}
		if pe.Phase != PhaseCleanup {
			t.Errorf("phase = %q, want %q", pe.Phase, PhaseCleanup)
		}
		if pe.Source != "payload.004" {
			t.Errorf("source = %q, want the OTA member", pe.Source)
		}
	})

	t.Run("does not discard the original error", func(t *testing.T) {
		orig := errors.New("extraction already failed")
		err := joinRemoveTempDir(orig, "", victim)
		if !errors.Is(err, orig) {
			t.Errorf("cleanup failure swallowed the original error %v", orig)
		}
	})

	t.Run("passes err through untouched on success", func(t *testing.T) {
		if err := joinRemoveTempDir(nil, "", t.TempDir()); err != nil {
			t.Errorf("joinRemoveTempDir(removable dir) = %v, want nil", err)
		}
	})

	// ExtractFromCryptexesWithSources returns ErrNoDscInCryptexes through the
	// same deferred joinRemoveTempDir, so the sentinel and a real cleanup
	// failure reach the caller inside ONE joined error. A caller that treats
	// errors.Is(err, ErrNoDscInCryptexes) as "nothing to report" would discard
	// the leak, so the join must stay inspectable leaf by leaf.
	t.Run("keeps the no-dsc sentinel and the leak distinguishable", func(t *testing.T) {
		err := joinRemoveTempDir(ErrNoDscInCryptexes, "", victim)
		if !errors.Is(err, ErrNoDscInCryptexes) {
			t.Errorf("error %v lost the ErrNoDscInCryptexes sentinel", err)
		}
		var pe *PhaseError
		if !errors.As(err, &pe) || pe.Phase != PhaseCleanup {
			t.Fatalf("error %v does not carry a %q PhaseError", err, PhaseCleanup)
		}
		joined, ok := err.(interface{ Unwrap() []error })
		if !ok {
			t.Fatalf("error %v is not a join; callers cannot filter the sentinel leaf out of it", err)
		}
		if n := len(joined.Unwrap()); n != 2 {
			t.Errorf("join holds %d leaves, want the sentinel and the cleanup failure", n)
		}
	})
}

// TestWrapPhaseClassifiesEachLeafOfAJoin pins that a join is attributed leaf by
// leaf. Classifying the join as a whole let one already-classified branch
// (typically a cleanup failure) shield its siblings, so the PRIMARY failure
// reached the report with no phase or source of its own.
func TestWrapPhaseClassifiesEachLeafOfAJoin(t *testing.T) {
	primary := errors.New("aa extract failed: exit status 1")
	cleanup := &PhaseError{Phase: PhaseCleanup, Source: "payload.001", Err: errors.New("device busy")}

	got := wrapPhase(PhasePayloadExtract, "payload.001", errors.Join(primary, cleanup))

	joined, ok := got.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("wrapPhase() = %T, want a joined error", got)
	}
	leaves := joined.Unwrap()
	if len(leaves) != 2 {
		t.Fatalf("got %d leaves, want 2", len(leaves))
	}

	var primaryPE *PhaseError
	if !errors.As(leaves[0], &primaryPE) {
		t.Fatalf("primary leaf %v was not classified", leaves[0])
	}
	if primaryPE.Phase != PhasePayloadExtract || primaryPE.Source != "payload.001" {
		t.Errorf("primary leaf = {%q %q}, want {payload-extract payload.001}", primaryPE.Phase, primaryPE.Source)
	}

	// The pre-classified cleanup leaf keeps its own attribution.
	var cleanupPE *PhaseError
	if !errors.As(leaves[1], &cleanupPE) || cleanupPE.Phase != PhaseCleanup {
		t.Errorf("cleanup leaf lost its phase: %v", leaves[1])
	}
	if !errors.Is(got, primary) {
		t.Error("wrapPhase dropped the primary error from the chain")
	}
}

// TestExtractPayloadToTempJoinsStagingCleanupFailure pins that when extraction
// fails AND the abandoned staging dir cannot be removed, both failures survive.
func TestExtractPayloadToTempJoinsStagingCleanupFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can unlink from a read-only directory")
	}
	parent := t.TempDir()
	victim := filepath.Join(parent, "staging")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

	primary := errors.New("aa extract failed: exit status 1")
	got := joinRemoveTempDir(primary, "payload.001", victim)

	if !errors.Is(got, primary) {
		t.Error("the cleanup failure swallowed the primary extraction error")
	}
	var pe *PhaseError
	if !errors.As(got, &pe) || pe.Phase != PhaseCleanup {
		t.Errorf("cleanup failure not attributed to %q: %v", PhaseCleanup, got)
	}
}

// TestExtractCryptexStagingCleanupIntegration is an integration check over two
// properties of ExtractCryptex's happy path:
//
//   - ordinary staging-directory cleanup: the temp dir it creates is gone when
//     the call returns; and
//   - ErrCryptexNotFound stays discoverable through errors.Is now that the
//     result passes through a cleanup join, which internal/diff branches on.
//
// It deliberately does NOT verify cleanup-FAILURE propagation. Making
// os.RemoveAll fail here would require an injectable remover on Reader, i.e.
// production state added solely for a test. That propagation is covered
// directly at the helper by TestJoinRemoveTempDirReportsFailure; this call site
// is a one-line, compile-checked delegation to it.
func TestExtractCryptexStagingCleanupIntegration(t *testing.T) {
	before, err := filepath.Glob(filepath.Join(os.TempDir(), "ota_extract_cryptexes*"))
	if err != nil {
		t.Fatal(err)
	}

	r := &Reader{}
	if _, err := r.ExtractCryptex("app", t.TempDir()); !errors.Is(err, ErrCryptexNotFound) {
		t.Fatalf("ExtractCryptex() error = %v, want ErrCryptexNotFound to survive the cleanup join", err)
	}

	after, err := filepath.Glob(filepath.Join(os.TempDir(), "ota_extract_cryptexes*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("staging dirs before=%d after=%d; ExtractCryptex leaked its temp dir", len(before), len(after))
	}

	if _, err := r.ExtractCryptex("bogus-type", t.TempDir()); err == nil {
		t.Error("ExtractCryptex(unknown type) = nil, want an error")
	}
}

// TestAnySystemCryptexSelectorCoversArm64_32 pins the unfiltered `--cryptex
// system` selector. `arm64e?` cannot match arm64_32, so a watchOS OTA carrying
// only cryptex-system-arm64_32 reported "cryptex not found" unless the caller
// named the arch explicitly.
func TestAnySystemCryptexSelectorCoversArm64_32(t *testing.T) {
	for _, name := range []string{
		"cryptex-system-arm64",
		"cryptex-system-arm64e",
		"cryptex-system-arm64_32",
		"cryptex-system-x86_64",
		"cryptex-system-x86_64h",
	} {
		if !reAnySystemCryptex.MatchString(name) {
			t.Errorf("reAnySystemCryptex does not match %q", name)
		}
	}
	for _, name := range []string{"cryptex-app", "cryptex-system-arm64_64", "cryptex-system-"} {
		if reAnySystemCryptex.MatchString(name) {
			t.Errorf("reAnySystemCryptex unexpectedly matches %q", name)
		}
	}
	// Every arch this selector accepts must also survive the DSC-cryptex filter.
	for _, name := range []string{"cryptex-system-arm64_32", "cryptex-system-arm64e"} {
		if !reOTADscCryptex.MatchString(name) {
			t.Errorf("reOTADscCryptex does not match %q; the two selectors have drifted", name)
		}
	}
}
