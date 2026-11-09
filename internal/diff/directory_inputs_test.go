package diff

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/blacktop/go-macho/types"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/testutil"
)

// TestMountDiffKeysMatchIPSWMode pins the key shape for OTA and directory
// inputs: mount-relative with a leading slash, as IPSW mode reports them, so
// the same file is listed identically whatever the input type.
func TestMountDiffKeysMatchIPSWMode(t *testing.T) {
	arm64 := testutil.MachoArch{CPU: types.CPUArm64}
	oldRoot, newRoot := t.TempDir(), t.TempDir()
	testutil.WriteMacho(t, filepath.Join(oldRoot, "bin", "tool"), arm64)
	testutil.WriteMacho(t, filepath.Join(oldRoot, "bin", "gone"), arm64)
	testutil.WriteMacho(t, filepath.Join(newRoot, "bin", "tool"), arm64)
	testutil.WriteMacho(t, filepath.Join(newRoot, "bin", "added"), arm64)
	if err := os.WriteFile(filepath.Join(newRoot, "notes.txt"), []byte("synthetic"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldMounts := map[string]mount{"filesystem": {MountPath: oldRoot}}
	newMounts := map[string]mount{"filesystem": {MountPath: newRoot}}

	machos, err := diffMachosInMounts(oldMounts, newMounts, &mcmd.DiffConfig{Markdown: true, DiffTool: "git"})
	if err != nil {
		t.Fatal(err)
	}
	got := machos["filesystem"]
	if got == nil || !slices.Equal(got.New, []string{"/bin/added"}) || !slices.Equal(got.Removed, []string{"/bin/gone"}) {
		t.Fatalf("Mach-O diff = %+v, want /bin/added new and /bin/gone removed", got)
	}

	files, err := diffFilesInMounts(oldMounts, newMounts)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/bin/added", "/notes.txt"}; !slices.Equal(files.New["filesystem"], want) {
		t.Errorf("new files = %v, want %v", files.New["filesystem"], want)
	}
	if want := []string{"/bin/gone"}; !slices.Equal(files.Removed["filesystem"], want) {
		t.Errorf("removed files = %v, want %v", files.Removed["filesystem"], want)
	}
}
