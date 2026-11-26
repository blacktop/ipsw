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

// Package skills embeds the ipsw agent skill and installs it into an agent's skills directory.
//
// The skill's source lives in skills/ipsw at the repository root, where npx skills and the
// Claude Code and Codex plugin marketplaces also read it. The binary embeds ipsw.zip, a
// deflate-compressed copy that `go generate ./internal/skills` rebuilds; a test fails when the
// two disagree.
package skills

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/blacktop/ipsw/internal/utils"
	"gopkg.in/yaml.v3"
)

//go:generate go run ./zipgen ../../skills/ipsw ipsw.zip

// Name is the skill's directory name and frontmatter name.
const Name = "ipsw"

//go:embed ipsw.zip
var archive []byte

func skillFS() (fs.FS, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("failed to open embedded skill archive: %w", err)
	}
	return zr, nil
}

// Version returns metadata.version from the embedded SKILL.md frontmatter.
func Version() (string, error) {
	skill, err := skillFS()
	if err != nil {
		return "", err
	}
	data, err := fs.ReadFile(skill, "SKILL.md")
	if err != nil {
		return "", fmt.Errorf("failed to read embedded SKILL.md: %w", err)
	}
	return parseVersion(data)
}

func parseVersion(skillMD []byte) (string, error) {
	rest, ok := bytes.CutPrefix(skillMD, []byte("---\n"))
	if !ok {
		return "", errors.New("SKILL.md does not start with a '---' frontmatter line")
	}
	frontmatter, _, ok := bytes.Cut(rest, []byte("\n---\n"))
	if !ok {
		return "", errors.New("SKILL.md frontmatter has no closing '---' line")
	}
	var meta struct {
		Metadata struct {
			Version string `yaml:"version"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(frontmatter, &meta); err != nil {
		return "", fmt.Errorf("failed to parse SKILL.md frontmatter: %w", err)
	}
	if meta.Metadata.Version == "" {
		return "", errors.New("SKILL.md frontmatter has no metadata.version")
	}
	return meta.Metadata.Version, nil
}

// errPreviousKept marks a failed install whose previous copy could not be moved back into place.
// That copy stays in the staging directory the error names.
var errPreviousKept = errors.New("previous skill kept")

// Install writes the embedded skill to skillsDir/ipsw and returns that path.
//
// An existing skillsDir/ipsw directory is replaced, so re-running Install after an upgrade
// refreshes the skill. The new copy is assembled in a hidden .ipsw-skill-* directory inside
// skillsDir. The previous copy is moved aside into that directory rather than deleted, removed
// only once the new copy is in place, and moved back if the new copy cannot take its place. If
// it cannot be moved back, or the process dies between the two moves, it is left in the
// .ipsw-skill-* directory. Install replaces only a directory: it refuses a symlink, which usually
// points at a checkout someone is editing, and any file or other entry at that path.
func Install(skillsDir string) (string, error) {
	return install(skillsDir, os.Rename)
}

func install(
	skillsDir string, rename func(oldpath, newpath string) error,
) (dest string, err error) {
	dest = filepath.Join(skillsDir, Name)
	if info, err := os.Lstat(dest); err == nil && !info.IsDir() {
		return "", fmt.Errorf(
			"%s is a symlink or file, not a skill directory; remove it to install the bundled skill",
			dest)
	}
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create skills directory %s: %w", skillsDir, err)
	}
	tmp, err := os.MkdirTemp(skillsDir, ".ipsw-skill-")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory in %s: %w", skillsDir, err)
	}
	keepStaging := false
	defer func() {
		if !keepStaging {
			utils.RemoveTempDir(tmp, &err)
		}
	}()

	skill, err := skillFS()
	if err != nil {
		return "", err
	}
	staged := filepath.Join(tmp, Name)
	if err := os.CopyFS(staged, skill); err != nil {
		return "", fmt.Errorf("failed to write skill files to %s: %w", staged, err)
	}
	if err := swapIn(staged, dest, filepath.Join(tmp, "previous"), rename); err != nil {
		keepStaging = errors.Is(err, errPreviousKept)
		return "", err
	}
	return dest, nil
}

// swapIn moves staged to dest. An existing dest is first moved to backup, and moved back if
// staged cannot take its place.
func swapIn(staged, dest, backup string, rename func(oldpath, newpath string) error) error {
	err := rename(dest, backup)
	hadPrevious := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to move previous skill at %s aside: %w", dest, err)
	}
	if err := rename(staged, dest); err != nil {
		err = fmt.Errorf("failed to move skill into %s: %w", dest, err)
		if !hadPrevious {
			return err
		}
		if restoreErr := rename(backup, dest); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("%w at %s: %w", errPreviousKept, backup, restoreErr))
		}
		return err
	}
	return nil
}
