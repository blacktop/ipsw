//go:build !ios

package download

import (
	"archive/zip"
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const syntheticIPAInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>TestExec</string></dict></plist>`

func writeSyntheticIPA(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, data := range map[string][]byte{
		"Payload/Test.app/Info.plist": []byte(syntheticIPAInfoPlist),
		"Payload/Test.app/TestExec":   []byte("synthetic executable"),
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func syntheticPatchInfo() *downloadAppResult {
	return &downloadAppResult{
		Metadata: map[string]any{},
		Sinfs:    []downloadSinfResult{{Data: []byte("synthetic sinf")}},
	}
}

func TestPatchIPAFailureRetainsStagedDownload(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "app.ipa.unpatched")
	dst := filepath.Join(dir, "app.ipa")

	// not a zip: applyPatches must fail before producing any output
	if err := os.WriteFile(staging, []byte("corrupt: not a zip archive"), 0o600); err != nil {
		t.Fatal(err)
	}

	as := &AppStore{}
	staged, err := os.Open(staging)
	if err != nil {
		t.Fatal(err)
	}
	err = as.patchIPA(staged, dst, &downloadAppResult{})
	if err == nil {
		t.Fatal("patchIPA() error = nil, want patch failure")
	}
	if _, statErr := os.Stat(staging); statErr != nil {
		t.Fatalf("staged download stat error = %v, want multi-GB source retained for retry", statErr)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatalf("dst stat error = %v, want no partial IPA published at the final path", statErr)
	}
	leftovers, globErr := filepath.Glob(dst + ".patching-*")
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(leftovers) != 0 {
		t.Fatalf("patching temp files left behind: %v", leftovers)
	}
}

func TestOpenMatchingStaging(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "app.ipa.unpatched")
	payload := []byte("synthetic ipa payload")
	if err := os.WriteFile(staging, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	goodMD5 := fmt.Sprintf("%x", md5.Sum(payload))

	matched := openMatchingStaging(staging, goodMD5)
	if matched == nil {
		t.Error("matching stage not reused")
	} else {
		matched.Close()
	}
	matched = openMatchingStaging(staging, strings.ToUpper(goodMD5))
	if matched == nil {
		t.Error("md5 comparison must be case-insensitive")
	} else {
		matched.Close()
	}
	if openMatchingStaging(staging, strings.Repeat("0", 32)) != nil {
		t.Error("corrupt/stale stage must not be reused")
	}
	if openMatchingStaging(staging, "") != nil {
		t.Error("stage without a published hash must not be trusted")
	}
	if openMatchingStaging(filepath.Join(dir, "missing.unpatched"), goodMD5) != nil {
		t.Error("missing stage must not be reused")
	}
}

func TestConcurrentPatchIPAsPinValidatedSource(t *testing.T) {
	for iteration := range 25 {
		dir := t.TempDir()
		staging := filepath.Join(dir, "app.ipa.unpatched")
		dst := filepath.Join(dir, "app.ipa")
		writeSyntheticIPA(t, staging)
		payload, err := os.ReadFile(staging)
		if err != nil {
			t.Fatal(err)
		}
		wantMD5 := fmt.Sprintf("%x", md5.Sum(payload))

		sources := []*os.File{
			openMatchingStaging(staging, wantMD5),
			openMatchingStaging(staging, wantMD5),
		}
		if sources[0] == nil || sources[1] == nil {
			t.Fatal("failed to open matching stages")
		}

		start := make(chan struct{})
		errs := make(chan error, len(sources))
		var wg sync.WaitGroup
		for _, source := range sources {
			wg.Go(func() {
				<-start
				errs <- (&AppStore{}).patchIPA(source, dst, syntheticPatchInfo())
			})
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("iteration %d concurrent patch failed: %v", iteration, err)
			}
		}

		reader, err := zip.OpenReader(dst)
		if err != nil {
			t.Fatalf("iteration %d final IPA is invalid: %v", iteration, err)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		leftovers, err := filepath.Glob(dst + ".patching-*")
		if err != nil {
			t.Fatal(err)
		}
		if len(leftovers) != 0 {
			t.Fatalf("iteration %d patch leftovers = %v", iteration, leftovers)
		}
	}
}

func TestPatchIPADoesNotRemoveReplacementStage(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "app.ipa.unpatched")
	dst := filepath.Join(dir, "app.ipa")
	writeSyntheticIPA(t, staging)
	payload, err := os.ReadFile(staging)
	if err != nil {
		t.Fatal(err)
	}
	staged := openMatchingStaging(staging, fmt.Sprintf("%x", md5.Sum(payload)))
	if staged == nil {
		t.Fatal("failed to open matching stage")
	}

	replacement := []byte("new stage from another process")
	replacementPath := filepath.Join(dir, "replacement.unpatched")
	if err := os.WriteFile(replacementPath, replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacementPath, staging); err != nil {
		t.Fatal(err)
	}
	if err := (&AppStore{}).patchIPA(staged, dst, syntheticPatchInfo()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(staging)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(replacement) {
		t.Fatalf("replacement stage = %q, want %q", got, replacement)
	}
}
