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

// Package skillzip packs a skill directory into the deflate-compressed zip that package skills
// embeds. Entries sit at the archive root, in sorted order, with a fixed timestamp and mode, so
// the same input always produces the same archive and a regenerated zip diffs only on real
// content changes.
package skillzip

import (
	"archive/zip"
	"compress/flate"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"
)

// epoch is the earliest time the zip DOS date format can hold.
var epoch = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

// Write packs the skill in src into a zip written to w. A skill ships only SKILL.md,
// LICENSE.txt, and Markdown files directly under references/; any other file is an error, so a
// crash log or other stray file left in the folder can never ship. Dot-files such as .DS_Store
// and agent state dirs such as .claude/ are skipped.
func Write(w io.Writer, src fs.FS) error {
	zw := zip.NewWriter(w)
	zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestCompression)
	})
	err := fs.WalkDir(src, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name != "." && strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file; skills may only contain regular files", name)
		}
		if !shipped(name) {
			return fmt.Errorf(
				"%s is not a skill file; skills ship only SKILL.md, LICENSE.txt and references/*.md",
				name)
		}
		return addFile(zw, src, name)
	})
	if err != nil {
		return fmt.Errorf("failed to pack skill: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("failed to finish zip: %w", err)
	}
	return nil
}

func shipped(name string) bool {
	if name == "SKILL.md" || name == "LICENSE.txt" {
		return true
	}
	dir, file := path.Split(name)
	return dir == "references/" && path.Ext(file) == ".md"
}

func addFile(zw *zip.Writer, src fs.FS, name string) error {
	data, err := fs.ReadFile(src, name)
	if err != nil {
		return err
	}
	header := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: epoch}
	header.SetMode(0o644)
	fw, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = fw.Write(data)
	return err
}
