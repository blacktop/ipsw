//go:build !ios && (darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package download

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestPatchIPARespectsUmask(t *testing.T) {
	if mask := os.Getenv("IPSW_TEST_PATCH_UMASK"); mask != "" {
		value, err := strconv.ParseUint(mask, 8, 32)
		if err != nil {
			t.Fatal(err)
		}
		old := syscall.Umask(int(value))
		defer syscall.Umask(old)

		dir := t.TempDir()
		staging := filepath.Join(dir, "app.ipa.unpatched")
		dst := filepath.Join(dir, "app.ipa")
		writeSyntheticIPA(t, staging)
		staged, err := os.Open(staging)
		if err != nil {
			t.Fatal(err)
		}
		if err := (&AppStore{}).patchIPA(staged, dst, syntheticPatchInfo()); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o644 &^ value)
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("patched IPA mode under umask %s = %04o, want %04o", mask, got, want)
		}
		return
	}

	for _, mask := range []string{"022", "077"} {
		t.Run(mask, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run", "^TestPatchIPARespectsUmask$")
			cmd.Env = append(os.Environ(), "IPSW_TEST_PATCH_UMASK="+mask)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("umask subprocess failed: %v\n%s", err, output)
			}
		})
	}
}
