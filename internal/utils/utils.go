package utils

import (
	"archive/zip"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
)

var normalPadding = cli.Default.Padding

func init() {
	rand.Seed(time.Now().Unix())
}

func RandomAgent() string {
	var userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38",
	}
	return userAgents[rand.Int()%len(userAgents)]
}

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
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}

	match := strings.EqualFold(sha1sum, fmt.Sprintf("%x", h.Sum(nil)))

	if !match {
		Indent(log.WithFields(log.Fields{
			"expected": sha1sum,
			"actual":   fmt.Sprintf("%x", h.Sum(nil)),
		}).Error, 3)("BAD CHECKSUM")
	}

	return match, nil
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

// WriteBuffer is a simple type that implements io.WriterAt on an in-memory buffer.
// The zero value of this type is an empty buffer ready to use.
// CREDIT: https://stackoverflow.com/a/46019585
type WriteBuffer struct {
	d []byte
	m int
}

// NewWriteBuffer creates and returns a new WriteBuffer with the given initial size and
// maximum. If maximum is <= 0 it is unlimited.
func NewWriteBuffer(size, max int) *WriteBuffer {
	if max < size && max >= 0 {
		max = size
	}
	return &WriteBuffer{make([]byte, size), max}
}

// SetMax sets the maximum capacity of the WriteBuffer. If the provided maximum is lower
// than the current capacity but greater than 0 it is set to the current capacity, if
// less than or equal to zero it is unlimited..
func (wb *WriteBuffer) SetMax(max int) {
	if max < len(wb.d) && max >= 0 {
		max = len(wb.d)
	}
	wb.m = max
}

// Bytes returns the WriteBuffer's underlying data. This value will remain valid so long
// as no other methods are called on the WriteBuffer.
func (wb *WriteBuffer) Bytes() []byte {
	return wb.d
}

// Shape returns the current WriteBuffer size and its maximum if one was provided.
func (wb *WriteBuffer) Shape() (int, int) {
	return len(wb.d), wb.m
}

func (wb *WriteBuffer) WriteAt(dat []byte, off int64) (int, error) {
	// Range/sanity checks.
	if int(off) < 0 {
		return 0, errors.New("Offset out of range (too small).")
	}
	if int(off)+len(dat) >= wb.m && wb.m > 0 {
		return 0, errors.New("Offset+data length out of range (too large).")
	}

	// Check fast path extension
	if int(off) == len(wb.d) {
		wb.d = append(wb.d, dat...)
		return len(dat), nil
	}

	// Check slower path extension
	if int(off)+len(dat) >= len(wb.d) {
		nd := make([]byte, int(off)+len(dat))
		copy(nd, wb.d)
		wb.d = nd
	}

	// Once no extension is needed just copy bytes into place.
	copy(wb.d[int(off):], dat)
	return len(dat), nil
}
