package skills

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/internal/skills/skillzip"
)

// sourceDir is the skill source, relative to this package.
const sourceDir = "../../skills/ipsw"

func embeddedFS(t *testing.T) fs.FS {
	t.Helper()
	skill, err := skillFS()
	if err != nil {
		t.Fatal(err)
	}
	return skill
}

// packedSourceFS is what `go generate ./internal/skills` would embed right now.
func packedSourceFS(t *testing.T) fs.FS {
	t.Helper()
	var buf bytes.Buffer
	if err := skillzip.Write(&buf, os.DirFS(sourceDir)); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

func readTree(t *testing.T, fsys fs.FS) map[string][]byte {
	t.Helper()
	tree := map[string][]byte{}
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(fsys, name)
		tree[name] = data
		return err
	})
	if err != nil {
		t.Fatalf("walk skill tree: %v", err)
	}
	return tree
}

func assertSameTree(t *testing.T, want, got fs.FS) {
	t.Helper()
	wantTree, gotTree := readTree(t, want), readTree(t, got)
	wantNames := slices.Sorted(maps.Keys(wantTree))
	if gotNames := slices.Sorted(maps.Keys(gotTree)); !slices.Equal(gotNames, wantNames) {
		t.Fatalf("file set = %v, want %v", gotNames, wantNames)
	}
	for _, name := range wantNames {
		if !bytes.Equal(gotTree[name], wantTree[name]) {
			t.Errorf("%s differs", name)
		}
	}
}

func TestEmbeddedArchiveMatchesSource(t *testing.T) {
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("skills/ipsw changed without regenerating ipsw.zip; run: go generate ./internal/skills")
		}
	})
	assertSameTree(t, packedSourceFS(t), embeddedFS(t))
}

func assertOnlySkillIn(t *testing.T, skillsDir string) {
	t.Helper()
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != Name {
		t.Errorf("%s holds %v, want only %s", skillsDir, entries, Name)
	}
}

func TestEmbeddedSkillVersion(t *testing.T) {
	version, err := Version()
	if err != nil {
		t.Fatalf("Version() error: %v", err)
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(version) {
		t.Errorf("Version() = %q, want MAJOR.MINOR.PATCH", version)
	}
}

func TestPluginManifestVersionsMatchSkill(t *testing.T) {
	want, err := Version()
	if err != nil {
		t.Fatal(err)
	}
	for _, manifest := range []string{
		"../../skills/.claude-plugin/plugin.json",
		"../../skills/.codex-plugin/plugin.json",
	} {
		data, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatal(err)
		}
		var plugin struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(data, &plugin); err != nil {
			t.Fatalf("parse %s: %v", manifest, err)
		}
		if plugin.Version != want {
			t.Errorf("%s version = %q, want SKILL.md metadata.version %q; bump them together",
				manifest, plugin.Version, want)
		}
	}
}

func TestEmbeddedSkillName(t *testing.T) {
	skillMD, err := fs.ReadFile(embeddedFS(t), "SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(skillMD), "\nname: "+Name+"\n") {
		t.Errorf("embedded SKILL.md frontmatter does not declare name: %s", Name)
	}
}

func TestParseVersionErrors(t *testing.T) {
	tests := map[string]string{
		"no frontmatter":    "# ipsw\n",
		"unclosed":          "---\nname: ipsw\n",
		"no version":        "---\nname: ipsw\nmetadata:\n  other: x\n---\nbody\n",
		"malformed yaml":    "---\nmetadata: [\n---\nbody\n",
		"version not under": "---\nversion: \"1.0.0\"\n---\nbody\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if v, err := parseVersion([]byte(input)); err == nil {
				t.Errorf("parseVersion() = %q, want error", v)
			}
		})
	}
}

func TestInstallCreatesMissingDirectories(t *testing.T) {
	skillsDir := filepath.Join(t.TempDir(), "home", ".agents", "skills")

	dest, err := Install(skillsDir)
	if err != nil {
		t.Fatalf("Install() error: %v", err)
	}
	if want := filepath.Join(skillsDir, Name); dest != want {
		t.Errorf("Install() = %q, want %q", dest, want)
	}
	assertSameTree(t, embeddedFS(t), os.DirFS(dest))
	assertOnlySkillIn(t, skillsDir)
}

func TestInstallReplacesPreviousCopy(t *testing.T) {
	skillsDir := t.TempDir()
	dest := filepath.Join(skillsDir, Name)
	stale := filepath.Join(dest, "references", "removed-in-new-release.md")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "SKILL.md"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Install(skillsDir); err != nil {
		t.Fatalf("Install() error: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale file from the previous copy survived: stat err = %v", err)
	}
	assertSameTree(t, embeddedFS(t), os.DirFS(dest))
	assertOnlySkillIn(t, skillsDir)
}

func TestInstallRefusesSymlink(t *testing.T) {
	skillsDir := t.TempDir()
	checkout := t.TempDir()
	sentinel := filepath.Join(checkout, "SKILL.md")
	if err := os.WriteFile(sentinel, []byte("work in progress"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(skillsDir, Name)
	if err := os.Symlink(checkout, link); err != nil {
		t.Fatal(err)
	}

	_, err := Install(skillsDir)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Install() error = %v, want symlink refusal", err)
	}
	if got, _ := os.ReadFile(sentinel); string(got) != "work in progress" {
		t.Errorf("symlink target was modified: %q", got)
	}
	if target, err := os.Readlink(link); err != nil || target != checkout {
		t.Errorf("symlink changed: target=%q err=%v", target, err)
	}
}

func TestInstallRefusesFileAtDestination(t *testing.T) {
	skillsDir := t.TempDir()
	dest := filepath.Join(skillsDir, Name)
	if err := os.WriteFile(dest, []byte("not a skill"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Install(skillsDir)
	if err == nil || !strings.Contains(err.Error(), "not a skill directory") {
		t.Fatalf("Install() error = %v, want refusal of a file at %s", err, dest)
	}
	if got, err := os.ReadFile(dest); err != nil || string(got) != "not a skill" {
		t.Errorf("file at destination changed: %q, err = %v", got, err)
	}
	assertOnlySkillIn(t, skillsDir)
}

// renameFailing behaves like os.Rename except that the listed calls, counted from 1, fail.
// Install renames the previous copy aside (1), the new copy into place (2), and, if that
// fails, the previous copy back (3).
func renameFailing(fail ...int) func(oldpath, newpath string) error {
	call := 0
	return func(oldpath, newpath string) error {
		call++
		if slices.Contains(fail, call) {
			return fmt.Errorf("injected failure on rename %d", call)
		}
		return os.Rename(oldpath, newpath)
	}
}

func installedOver(t *testing.T, previous string) (skillsDir, dest string) {
	t.Helper()
	skillsDir = t.TempDir()
	dest = filepath.Join(skillsDir, Name)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "SKILL.md"), []byte(previous), 0o644); err != nil {
		t.Fatal(err)
	}
	return skillsDir, dest
}

func TestInstallRestoresPreviousWhenReplaceFails(t *testing.T) {
	skillsDir, dest := installedOver(t, "previous")

	if _, err := install(skillsDir, renameFailing(2)); err == nil {
		t.Fatal("install() succeeded although moving the new copy into place failed")
	}
	got, err := os.ReadFile(filepath.Join(dest, "SKILL.md"))
	if err != nil || string(got) != "previous" {
		t.Errorf("previous copy not restored: SKILL.md = %q, err = %v", got, err)
	}
	assertOnlySkillIn(t, skillsDir)
}

func TestInstallKeepsPreviousWhenRestoreFails(t *testing.T) {
	skillsDir, _ := installedOver(t, "previous")

	_, err := install(skillsDir, renameFailing(2, 3))
	if !errors.Is(err, errPreviousKept) {
		t.Fatalf("install() error = %v, want errPreviousKept", err)
	}
	kept, globErr := filepath.Glob(filepath.Join(skillsDir, ".ipsw-skill-*", "previous", "SKILL.md"))
	if globErr != nil || len(kept) != 1 {
		t.Fatalf("previous copy not kept in a staging directory: %v %v", kept, globErr)
	}
	if got, _ := os.ReadFile(kept[0]); string(got) != "previous" {
		t.Errorf("kept SKILL.md = %q, want the previous copy", got)
	}
	if !strings.Contains(err.Error(), filepath.Dir(kept[0])) {
		t.Errorf("error %q does not name the kept copy %s", err, filepath.Dir(kept[0]))
	}
}

func TestInstallFailsWhenSkillsDirIsAFile(t *testing.T) {
	skillsDir := filepath.Join(t.TempDir(), "skills")
	if err := os.WriteFile(skillsDir, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(skillsDir); err == nil {
		t.Fatal("Install() succeeded with a file in place of the skills directory")
	}
}
