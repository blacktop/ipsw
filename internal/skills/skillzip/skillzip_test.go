package skillzip

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func TestWriteLeavesOutDotFiles(t *testing.T) {
	skill := fstest.MapFS{
		"SKILL.md":             {Data: []byte("---\nname: demo\n---\n")},
		"LICENSE.txt":          {Data: []byte("MIT\n")},
		"references/kernel.md": {Data: []byte("# kernel\n")},
		"references/dyld.md":   {Data: []byte("# dyld\n")},
	}
	withJunk := fstest.MapFS{
		".DS_Store":                   {Data: []byte("finder")},
		".claude/settings.local.json": {Data: []byte("{}")},
		"references/.DS_Store":        {Data: []byte("finder")},
	}
	maps.Copy(withJunk, skill)

	var buf bytes.Buffer
	if err := Write(&buf, withJunk); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range zr.File {
		got = append(got, f.Name)
	}
	if want := slices.Sorted(maps.Keys(skill)); !slices.Equal(got, want) {
		t.Errorf("archive entries = %v, want %v", got, want)
	}
	for name, file := range skill {
		data, err := fs.ReadFile(zr, name)
		if err != nil || !bytes.Equal(data, file.Data) {
			t.Errorf("%s did not round-trip: err=%v", name, err)
		}
	}
}

func TestWriteRejectsFilesOutsideTheSkillLayout(t *testing.T) {
	for _, stray := range []string{
		"crash.ips",
		"references/out.golden",
		"notes.txt",
		"references/nested/a.md",
		"scripts/run.sh",
	} {
		t.Run(stray, func(t *testing.T) {
			src := fstest.MapFS{
				"SKILL.md": {Data: []byte("---\nname: demo\n---\n")},
				stray:      {Data: []byte("not part of the skill")},
			}
			var buf bytes.Buffer
			err := Write(&buf, src)
			if err == nil || !strings.Contains(err.Error(), stray) {
				t.Fatalf("Write() error = %v, want a refusal naming %s", err, stray)
			}
		})
	}
}

func TestWriteRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("SKILL.md", filepath.Join(dir, "link.md")); err != nil {
		t.Fatal(err)
	}
	err := Write(&bytes.Buffer{}, os.DirFS(dir))
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Write() error = %v, want regular-file refusal", err)
	}
}
