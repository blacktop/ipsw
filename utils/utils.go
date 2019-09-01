package utils

import (
	"archive/zip"
	"crypto/sha1"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
)

var normalPadding = cli.Default.Padding

// Indent indents apex log line to supplied level
func Indent(f func(s string), level int) func(string) {
	return func(s string) {
		cli.Default.Padding = normalPadding * level
		f(s)
		cli.Default.Padding = normalPadding
	}
}

func getFmtStr() string {
	if runtime.GOOS == "windows" {
		return "%s"
	}
	return "\033[1m%s\033[0m"
}

// StrSliceContains returns true if string slice contains given string
func StrSliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.Contains(strings.ToLower(item), strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// Unique returns a slice with only unique strings
func Unique(s []string) []string {
	unique := make(map[string]bool, len(s))
	us := make([]string, len(unique))
	for _, elem := range s {
		if len(elem) != 0 {
			if !unique[elem] {
				us = append(us, elem)
				unique[elem] = true
			}
		}
	}

	return us
}

// Verify verifies the downloaded against it's hash
func Verify(sha1sum, name string) (bool, error) {
	Indent(log.Info, 1)("verifying sha1sum...")
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}

	Indent(log.WithFields(log.Fields{
		"api":  sha1sum,
		"file": fmt.Sprintf("%x", h.Sum(nil)),
	}).Debug, 1)("sha1 hashes")
	return strings.EqualFold(sha1sum, fmt.Sprintf("%x", h.Sum(nil))), nil
}

// Unzip - https://stackoverflow.com/a/24792688
func Unzip(src, dest string, filter func(f *zip.File) bool) ([]string, error) {

	var fNames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

	os.MkdirAll(dest, 0755)

	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		path := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
		} else {
			// TODO: add the ability to preserve folder structure if user wants
			// os.MkdirAll(filepath.Dir(path), f.Mode())
			f, err := os.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range r.File {
		if filter(f) {
			fNames = append(fNames, path.Base(f.Name))
			err := extractAndWriteFile(f)
			if err != nil {
				return nil, err
			}
		}
	}

	return fNames, nil
}
