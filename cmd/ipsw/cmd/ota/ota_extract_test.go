package ota

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/ota"
)

func TestValidateOTAExtractArgs(t *testing.T) {
	tests := []struct {
		name    string
		flags   otaExtractFlags
		wantErr string
	}{
		{
			name:  "dyld with confirm is accepted",
			flags: otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, confirm: true},
		},
		{
			name:    "confirm alone is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip"}, confirm: true},
			wantErr: "--confirm requires --pattern or --dyld",
		},
		{
			name:  "dyld with range is accepted",
			flags: otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, payloadRange: `payload\.0\d+`},
		},
		{
			name:  "dyld with json is accepted",
			flags: otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, json: true},
		},
		{
			name:  "dyld with multiple architectures is accepted",
			flags: otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, dyldArches: []string{"arm64e", "x86_64"}},
		},
		{
			name:  "json accepts arm64_32",
			flags: otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, json: true, dyldArches: []string{"arm64_32"}},
		},
		{
			name:    "dyld architecture without dyld is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip"}, dyldArches: []string{"arm64e"}},
			wantErr: "--dyld-arch or -a can only be used with --dyld or -d",
		},
		{
			name:    "unknown dyld architecture is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, dyldArches: []string{"mips"}},
			wantErr: "invalid --dyld-arch: 'mips'",
		},
		{
			name:  "pattern with range is accepted",
			flags: otaExtractFlags{args: []string{"OTA.zip"}, pattern: "foo", payloadRange: "bar"},
		},
		{
			name:    "range alone is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip"}, payloadRange: "bar"},
			wantErr: "--range requires --pattern or --dyld",
		},
		{
			name:    "json without dyld is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip"}, json: true},
			wantErr: "--json requires --dyld",
		},
		{
			name:    "json with kernel is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, kernel: true, json: true},
			wantErr: "--json cannot be combined with",
		},
		{
			name:    "json with cryptex is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, cryptex: "system", json: true},
			wantErr: "--json cannot be combined with",
		},
		{
			name:    "dyld with pattern is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, pattern: "foo"},
			wantErr: "cannot use --dyld with --pattern",
		},
		{
			name:    "dyld with flat is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, flat: true},
			wantErr: "--flat is not supported with --dyld",
		},
		{
			name:  "dyld with kernel and flat is accepted",
			flags: otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, kernel: true, flat: true},
		},
		{
			name:    "json with flat is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, json: true, flat: true},
			wantErr: "--flat is not supported with --dyld",
		},
		{
			name:    "filename with pattern is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip", "some/file"}, pattern: "foo"},
			wantErr: "cannot use both FILENAME and --pattern",
		},
		{
			name:    "filename with dyld is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip", "some/file"}, dyld: true},
			wantErr: "cannot use FILENAME with --cryptex, --dyld, or --kernel",
		},
		{
			name:    "filename with cryptex is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip", "some/file"}, cryptex: "system"},
			wantErr: "cannot use FILENAME with --cryptex, --dyld, or --kernel",
		},
		{
			name:    "no args is rejected",
			flags:   otaExtractFlags{},
			wantErr: "accepts between 1 and 2 arg(s)",
		},
		{
			name:    "too many args is rejected",
			flags:   otaExtractFlags{args: []string{"OTA.zip", "a", "b"}},
			wantErr: "accepts between 1 and 2 arg(s)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOTAExtractArgs(tt.flags)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateOTAExtractArgs() unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateOTAExtractArgs() error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateOTAExtractArgs() error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

// TestValidateOTAExtractArgsConfirmRequiresTarget guards both halves of the
// --confirm rule: it was widened to admit --dyld, but it still needs SOME
// target. Neither --confirm nor --range is a target flag, so a bare --confirm
// would otherwise fall through to extracting the whole archive.
func TestValidateOTAExtractArgsConfirmRequiresTarget(t *testing.T) {
	for _, f := range []otaExtractFlags{
		{args: []string{"OTA.zip"}, dyld: true, confirm: true},
		{args: []string{"OTA.zip"}, pattern: "kernelcache", confirm: true},
	} {
		if err := validateOTAExtractArgs(f); err != nil {
			t.Errorf("validateOTAExtractArgs(%+v) error = %q, want nil", f, err)
		}
	}

	bare := otaExtractFlags{args: []string{"OTA.zip"}, confirm: true}
	err := validateOTAExtractArgs(bare)
	if err == nil {
		t.Fatal("validateOTAExtractArgs(--confirm alone) = nil, want a rejection")
	}
	if !strings.Contains(err.Error(), "--confirm requires") {
		t.Errorf("error = %q, want it to name the missing target", err)
	}
	if bare.targeted() {
		t.Error("targeted() = true for --confirm alone; the rejection above is the only thing preventing full-archive extraction")
	}
}

// TestValidateOTAExtractArgsFlatStaysUsableAlongsideDyld pins that --flat is
// only rejected when --dyld is the sole extraction that could consume it.
// `--dyld --kernel --flat` extracted a flattened kernelcache before --dyld
// grew a report, so rejecting it outright would extract nothing at all where
// the same invocation previously produced both.
func TestValidateOTAExtractArgsFlatStaysUsableAlongsideDyld(t *testing.T) {
	tests := []struct {
		name     string
		flags    otaExtractFlags
		rejected bool
	}{
		{
			name:     "flat with dyld alone has no consumer",
			flags:    otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, flat: true},
			rejected: true,
		},
		{
			name:  "flat applies to the kernelcache alongside dyld",
			flags: otaExtractFlags{args: []string{"OTA.zip"}, dyld: true, kernel: true, flat: true},
		},
		{
			name:  "flat with kernel alone is untouched",
			flags: otaExtractFlags{args: []string{"OTA.zip"}, kernel: true, flat: true},
		},
		{
			name:  "flat with pattern alone is untouched",
			flags: otaExtractFlags{args: []string{"OTA.zip"}, pattern: "kernelcache", flat: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOTAExtractArgs(tt.flags)
			if tt.rejected {
				if err == nil || !strings.Contains(err.Error(), "--flat is not supported with --dyld") {
					t.Fatalf("validateOTAExtractArgs() error = %v, want the --flat rejection", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateOTAExtractArgs() error = %q, want nil", err)
			}
		})
	}
}

// TestTargetedExtractsRunKeepsGoingAfterDyldFailure pins that a --dyld failure
// only contributes to the exit code: `--dyld --kernel` extracted the
// kernelcache before --dyld reported failures at all, and must still do so.
func TestTargetedExtractsRunKeepsGoingAfterDyldFailure(t *testing.T) {
	dyldErr := errors.New("failed to patch cryptex-system-arm64e")
	var ran []string

	tx := targetedExtracts{
		dyld: func() error {
			ran = append(ran, "dyld")
			return dyldErr
		},
		kernel: func() error {
			ran = append(ran, "kernel")
			return nil
		},
	}

	err := tx.run()

	if want := []string{"dyld", "kernel"}; !slices.Equal(ran, want) {
		t.Fatalf("steps run = %v, want %v", ran, want)
	}
	if !errors.Is(err, dyldErr) {
		t.Fatalf("run() error = %v, want the dyld failure", err)
	}
}

func TestTargetedExtractsRunStepOrderAndCancellation(t *testing.T) {
	boom := errors.New("boom")
	allSteps := func(ran *[]string, failing string) targetedExtracts {
		step := func(name string) func() error {
			return func() error {
				*ran = append(*ran, name)
				if name == failing {
					return boom
				}
				return nil
			}
		}
		return targetedExtracts{
			cryptex: step("cryptex"),
			dyld:    step("dyld"),
			kernel:  step("kernel"),
			pattern: step("pattern"),
		}
	}

	tests := []struct {
		name    string
		failing string
		wantRan []string
		wantErr bool
	}{
		{
			name:    "all steps succeed",
			wantRan: []string{"cryptex", "dyld", "kernel", "pattern"},
		},
		{
			name:    "cryptex failure cancels the rest",
			failing: "cryptex",
			wantRan: []string{"cryptex"},
			wantErr: true,
		},
		{
			name:    "dyld failure cancels nothing",
			failing: "dyld",
			wantRan: []string{"cryptex", "dyld", "kernel", "pattern"},
			wantErr: true,
		},
		{
			name:    "kernel failure cancels the pattern step",
			failing: "kernel",
			wantRan: []string{"cryptex", "dyld", "kernel"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ran []string
			err := allSteps(&ran, tt.failing).run()
			if !slices.Equal(ran, tt.wantRan) {
				t.Fatalf("steps run = %v, want %v", ran, tt.wantRan)
			}
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("run() error = %v, want error: %v", err, tt.wantErr)
			}
		})
	}
}

func TestTargetedExtractsRunJoinsDyldAndLaterFailures(t *testing.T) {
	dyldErr := errors.New("dyld boom")
	kernelErr := errors.New("kernel boom")

	err := targetedExtracts{
		dyld:    func() error { return dyldErr },
		kernel:  func() error { return kernelErr },
		pattern: func() error { t.Fatal("pattern step ran after the kernel step failed"); return nil },
	}.run()

	if !errors.Is(err, dyldErr) || !errors.Is(err, kernelErr) {
		t.Fatalf("run() error = %v, want both the dyld and kernel failures", err)
	}
}

// TestReportPreExtractFailureEmitsJSON pins requirement 7: a handled failure
// that happens before extraction can start still produces one report.
func TestReportPreExtractFailureEmitsJSON(t *testing.T) {
	cause := errors.New("failed to open OTA file: no such file or directory")

	var buf bytes.Buffer
	err := reportPreExtractFailure(&buf, otaExtractFlags{json: true, dyld: true}, ota.PhaseOTAOpen, cause)

	if !errors.Is(err, cause) {
		t.Fatalf("reportPreExtractFailure() error = %v, want the original cause", err)
	}
	got := buf.String()
	if !strings.HasSuffix(got, "\n") || strings.Count(got, "\n") != 1 {
		t.Fatalf("report = %q, want exactly one trailing newline", got)
	}
	var rep struct {
		SchemaVersion int  `json:"schema_version"`
		Complete      bool `json:"complete"`
		Files         []struct{}
		Errors        []struct {
			Phase   string `json:"phase"`
			Source  string `json:"source"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal([]byte(got), &rep); err != nil {
		t.Fatalf("report is not valid JSON: %v (%q)", err, got)
	}
	if rep.SchemaVersion != dscSchemaVersion || rep.Complete {
		t.Fatalf("report = %+v, want schema_version %d and complete=false", rep, dscSchemaVersion)
	}
	if len(rep.Errors) != 1 || rep.Errors[0].Phase != string(ota.PhaseOTAOpen) {
		t.Fatalf("report.errors = %+v, want a single %q entry", rep.Errors, ota.PhaseOTAOpen)
	}
	if rep.Errors[0].Message != cause.Error() {
		t.Errorf("report.errors[0].message = %q, want %q", rep.Errors[0].Message, cause)
	}
}

func TestReportPreExtractFailurePromotesInnerPhase(t *testing.T) {
	cause := fmt.Errorf("failed to open OTA file: %w", &ota.PhaseError{
		Phase: ota.PhaseAEADecrypt,
		Err:   errors.New("no key found"),
	})

	var buf bytes.Buffer
	reportPreExtractFailure(&buf, otaExtractFlags{json: true, dyld: true}, ota.PhaseOTAOpen, cause)

	if want := `"phase":"aea-decrypt"`; !strings.Contains(buf.String(), want) {
		t.Fatalf("report = %s, want substring %s", buf.String(), want)
	}
}

// TestReportPreExtractFailureStaysSilentWithoutJSON pins that human mode keeps
// stdout empty and the error unchanged.
func TestReportPreExtractFailureStaysSilentWithoutJSON(t *testing.T) {
	cause := errors.New("failed to open OTA file: no such file or directory")

	var buf bytes.Buffer
	err := reportPreExtractFailure(&buf, otaExtractFlags{dyld: true}, ota.PhaseOTAOpen, cause)

	if err != cause {
		t.Fatalf("reportPreExtractFailure() error = %v, want the original cause unchanged", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("wrote %q to stdout without --json, want nothing", buf.String())
	}
}

// TestValidateOTAExtractArgsRejectsMalformedRange pins that a bad --range is
// rejected up front. It reaches regexp.MustCompile deep inside the payloadv2
// scan, so without this guard `--dyld --range '['` panics instead of reporting.
func TestValidateOTAExtractArgsRejectsMalformedRange(t *testing.T) {
	// The --json row also pins the documented exit behavior: a malformed
	// --range is an INVOCATION failure, rejected before a report exists, so it
	// can never surface as a payload-extract entry on stdout.
	for _, f := range []otaExtractFlags{
		{args: []string{"ota.zip"}, dyld: true, payloadRange: "["},
		{args: []string{"ota.zip"}, dyld: true, json: true, payloadRange: "["},
		{args: []string{"ota.zip"}, pattern: "kernelcache", payloadRange: "payload[.("},
	} {
		err := validateOTAExtractArgs(f)
		if err == nil {
			t.Fatalf("validateOTAExtractArgs(%+v) = nil, want an invalid-regex error", f)
		}
		if !strings.Contains(err.Error(), "invalid --range regex") {
			t.Errorf("error = %q, want it to name the offending flag", err)
		}
	}

	valid := otaExtractFlags{args: []string{"ota.zip"}, dyld: true, payloadRange: `^payload\.0[0-9]+$`}
	if err := validateOTAExtractArgs(valid); err != nil {
		t.Errorf("validateOTAExtractArgs(valid --range) = %v, want nil", err)
	}
}

func TestMatchesPostBOMPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{
			name:    "matches full path",
			pattern: `^System/Library/Caches/com\.apple\.dyld/`,
			path:    "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
			want:    true,
		},
		{
			name:    "matches basename",
			pattern: `^dyld_shared_cache`,
			path:    "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
			want:    true,
		},
		{
			name:    "does not match",
			pattern: `^kernelcache`,
			path:    "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re := regexp.MustCompile(tt.pattern)
			if got := matchesPostBOMPattern(re, tt.path); got != tt.want {
				t.Fatalf("matchesPostBOMPattern(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestOutputPathForExtraction(t *testing.T) {
	tests := []struct {
		name      string
		outputDir string
		path      string
		flat      bool
		want      string
		wantErr   bool
	}{
		{
			name:      "preserve directory structure",
			outputDir: "/tmp/out",
			path:      "System/Library/foo",
			flat:      false,
			want:      filepath.Join("/tmp/out", "System/Library/foo"),
		},
		{
			name:      "flat output",
			outputDir: "/tmp/out",
			path:      "System/Library/foo",
			flat:      true,
			want:      filepath.Join("/tmp/out", "foo"),
		},
		{
			name:      "reject traversal",
			outputDir: "/tmp/out",
			path:      "../../../etc/passwd",
			flat:      false,
			wantErr:   true,
		},
		{
			name:      "reject nested traversal",
			outputDir: "/tmp/out",
			path:      "foo/../../../etc/passwd",
			flat:      false,
			wantErr:   true,
		},
		{
			name:      "flat mode neutralizes traversal",
			outputDir: "/tmp/out",
			path:      "../../../etc/passwd",
			flat:      true,
			want:      filepath.Join("/tmp/out", "passwd"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := outputPathForExtraction(tt.outputDir, tt.path, tt.flat)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("outputPathForExtraction(%q, %q, %t) = %q, want error", tt.outputDir, tt.path, tt.flat, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("outputPathForExtraction(%q, %q, %t) unexpected error: %v", tt.outputDir, tt.path, tt.flat, err)
			}
			if got != tt.want {
				t.Fatalf("outputPathForExtraction(%q, %q, %t) = %q, want %q", tt.outputDir, tt.path, tt.flat, got, tt.want)
			}
		})
	}
}

// TestRunDyldExtractHumanModePropagatesFallbackFailure pins the human-mode exit
// contract. "Searched everywhere, found nothing" stays exit 0, but a REAL
// source failure must still propagate even when another source produced files:
// before the report existed those errors returned straight out of RunE.
func TestRunDyldExtractHumanModePropagatesFallbackFailure(t *testing.T) {
	t.Run("real failure alongside materialized files is fatal", func(t *testing.T) {
		rep := newDSCReport()
		rep.addFile("out", "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e", sourcePayloadV2)
		rep.addErrors(ota.PhaseCopy, sourceOTAAsset, errors.New("no space left on device"))
		if rep.finish().fatalErr() == nil {
			t.Error("fatalErr() = nil; a failed fallback source must not exit 0 just because another source succeeded")
		}
	})

	t.Run("found nothing anywhere stays non-fatal", func(t *testing.T) {
		rep := extractDSC(&fakeDSCSource{cryptexErr: ota.ErrNoDscInCryptexes}, testOpts())
		if rep.Complete {
			t.Error("report.Complete = true, want false (JSON mode still fails)")
		}
		if err := rep.fatalErr(); err != nil {
			t.Errorf("fatalErr() = %v, want nil so human mode keeps exiting 0", err)
		}
	})
}

// failingOTA yields a reader that errors part way through, so the copy fails
// AFTER it would previously have truncated the destination.
type failingOTA struct{ afterBytes int }

func (f failingOTA) Open(name string, decomp bool) (fs.File, error) {
	return failingFile{r: io.MultiReader(
		bytes.NewReader(bytes.Repeat([]byte("N"), f.afterBytes)),
		errReader{},
	)}, nil
}

type failingFile struct{ r io.Reader }

func (f failingFile) Stat() (fs.FileInfo, error) { return nil, nil }
func (f failingFile) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f failingFile) Close() error               { return nil }

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("input/output error") }

// TestCopyOTAFileToPathNeverDestroysExistingFile pins the transactional
// overwrite. Writing straight to outputPath truncated on os.Create, so a later
// failure — a bad read, or even a failed Close leaving unverified bytes — wiped
// out whatever an earlier extraction source had already materialized there.
func TestCopyOTAFileToPathNeverDestroysExistingFile(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dyld_shared_cache_arm64e")
	original := []byte("the cryptex-materialized cache")
	if err := os.WriteFile(dst, original, 0o644); err != nil {
		t.Fatal(err)
	}

	err := copyOTAFileToPath(failingOTA{afterBytes: 8}, "some/member", false, dst)
	if err == nil {
		t.Fatal("copyOTAFileToPath() = nil, want the read failure")
	}

	got, rerr := os.ReadFile(dst)
	if rerr != nil {
		t.Fatalf("prior file was destroyed by a failed copy: %v", rerr)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("prior file contents = %q, want %q (a failed copy must not disturb it)", got, original)
	}

	// No .partial-* staging files may survive.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".partial-") {
			t.Errorf("staging file %q leaked after a failed copy", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want just the original file", len(entries))
	}
}

// okOTA yields a fixed payload so a copy succeeds.
type okOTA struct{ data string }

func (o okOTA) Open(name string, decomp bool) (fs.File, error) {
	return failingFile{r: strings.NewReader(o.data)}, nil
}

// TestCopyOTAFileToPathMetadataContract pins the permission contract. Staging
// and renaming must not become a way to change a file's mode: an existing
// destination keeps its own permissions, and a new one lands exactly where
// os.Create would have, umask included.
func TestCopyOTAFileToPathMetadataContract(t *testing.T) {
	t.Run("existing destination keeps its permissions", func(t *testing.T) {
		// 0666 and 0664 carry bits a normal umask strips, so they are the modes
		// that actually prove the staging file is restored to the destination's
		// permissions rather than merely inheriting umask-masked ones.
		for _, mode := range []os.FileMode{0o600, 0o640, 0o755, 0o664, 0o666} {
			dir := t.TempDir()
			dst := filepath.Join(dir, "dyld_shared_cache_arm64e")
			if err := os.WriteFile(dst, []byte("old"), mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dst, mode); err != nil { // defeat the umask on create
				t.Fatal(err)
			}

			// Compare against what the filesystem actually reports, not the mode
			// we asked for: Windows normalizes every file to 0666 or 0444, so a
			// literal Unix mode would fail there despite correct behavior. On
			// Unix `before` equals `mode`, keeping the mutation coverage intact.
			beforeFI, err := os.Stat(dst)
			if err != nil {
				t.Fatal(err)
			}
			before := beforeFI.Mode().Perm()

			if err := copyOTAFileToPath(okOTA{data: "new"}, "member", false, dst); err != nil {
				t.Fatalf("copyOTAFileToPath() error = %v", err)
			}

			fi, err := os.Stat(dst)
			if err != nil {
				t.Fatal(err)
			}
			if got := fi.Mode().Perm(); got != before {
				t.Errorf("overwrote a %v file and it became %v; permissions must survive", before, got)
			}
			if data, _ := os.ReadFile(dst); string(data) != "new" {
				t.Errorf("contents = %q, want the new payload", data)
			}
		}
	})

	t.Run("new destination matches os.Create under the same umask", func(t *testing.T) {
		dir := t.TempDir()

		// Reference: what a plain os.Create produces right now, umask included.
		ref := filepath.Join(dir, "reference")
		f, err := os.Create(ref)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		refFI, err := os.Stat(ref)
		if err != nil {
			t.Fatal(err)
		}

		dst := filepath.Join(dir, "dyld_shared_cache_arm64e")
		if err := copyOTAFileToPath(okOTA{data: "new"}, "member", false, dst); err != nil {
			t.Fatalf("copyOTAFileToPath() error = %v", err)
		}
		fi, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := fi.Mode().Perm(), refFI.Mode().Perm(); got != want {
			t.Errorf("new file mode = %v, want %v (what os.Create yields under this umask)", got, want)
		}
	})

	t.Run("no staging files survive a successful copy", func(t *testing.T) {
		dir := t.TempDir()
		dst := filepath.Join(dir, "dyld_shared_cache_arm64e")
		if err := copyOTAFileToPath(okOTA{data: "new"}, "member", false, dst); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || strings.Contains(entries[0].Name(), ".partial") {
			t.Errorf("directory = %v, want only the finished file", entries)
		}
	})
}
