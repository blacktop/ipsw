package utils

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

var normalPadding = cli.Default.Padding

// Retry will retry a function f a number of attempts with a sleep duration in between
func Retry(attempts int, sleep time.Duration, f func() error) error {
	_, err := RetryWithResult(attempts, sleep, func() (struct{}, error) {
		return struct{}{}, f()
	})
	return err
}

type StopRetryingError struct {
	Err error
}

func (e *StopRetryingError) Error() string {
	return e.Err.Error()
}

// RetryWithResult will retry a function f a number of attempts with a sleep duration in between, returning the result if successful
func RetryWithResult[T any](attempts int, sleep time.Duration, f func() (T, error)) (result T, err error) {
	for i := 0; i < attempts; i++ {
		if i > 0 {
			Indent(log.Debug, 2)(fmt.Sprintf("retrying after error: %s", err))
			time.Sleep(sleep)
			sleep *= 2
		}
		result, err = f()
		if err == nil {
			return result, nil
		}
		// If StopRetryingError is returned, unwrap and return immediately
		var stopErr *StopRetryingError
		if errors.As(err, &stopErr) {
			return result, stopErr.Err
		}
	}
	return result, fmt.Errorf("after %d attempts, last error: %s", attempts, err)
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

// Uint64SliceContains returns true if uint64 slice contains given uint64
func Uint64SliceContains(slice []uint64, item uint64) bool {
	return slices.Contains(slice, item)
}

// Unique returns a slice with only unique elements
func Unique[T comparable](s []T) []T {
	inResult := make(map[T]bool)
	var result []T
	for _, str := range s {
		if _, ok := inResult[str]; !ok {
			inResult[str] = true
			result = append(result, str)
		}
	}
	return result
}

func UniqueAppend[T comparable](slice []T, i T) []T {
	if slices.Contains(slice, i) {
		return slice
	}
	return append(slice, i)
}

func UniqueConcat[T comparable](slice []T, in []T) []T {
	for _, i := range in {
		if slices.Contains(slice, i) {
			return slice
		}
		slice = append(slice, i)
	}
	return slice
}

type Pair[T, U any] struct {
	First  T
	Second U
}

func Zip[T, U any](ts []T, us []U) ([]Pair[T, U], error) {
	if len(ts) != len(us) {
		return nil, fmt.Errorf("slices have different lengths")
	}
	pairs := make([]Pair[T, U], len(ts))
	for i := range ts {
		pairs[i] = Pair[T, U]{ts[i], us[i]}
	}
	return pairs, nil
}

func Reverse[T any](input []T) {
	for i, j := 0, len(input)-1; i < j; i, j = i+1, j-1 {
		input[i], input[j] = input[j], input[i]
	}
}

func Difference[T comparable](a []T, b []T) []T {
	amap := make(map[T]bool)
	for _, item := range a {
		amap[item] = true
	}
	for _, item := range b {
		delete(amap, item)
	}
	return slices.Collect(maps.Keys(amap))
}

// ReverseBytes reverse byte array order
func ReverseBytes(a []byte) []byte {
	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}
	return a
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

// SearchZip searches for files in a zip.Reader
func SearchZip(files []*zip.File, pattern *regexp.Regexp, folder string, flat, progress bool) ([]string, error) {
	var fname string
	var artifacts []string

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %v", err)
	}

	found := false
	for _, f := range files {
		if pattern.MatchString(f.Name) {
			if f.FileInfo().IsDir() {
				continue
			}
			found = true
			if flat {
				fname = filepath.Join(folder, filepath.Base(f.Name))
			} else {
				fname = filepath.Join(folder, filepath.Clean(f.Name))
			}

			if err := os.MkdirAll(filepath.Dir(fname), 0750); err != nil {
				return nil, fmt.Errorf("failed to create directory %s: %v", filepath.Dir(fname), err)
			}

			var r io.ReadCloser
			if _, err := os.Stat(fname); os.IsNotExist(err) {
				rc, err := f.Open()
				if err != nil {
					return nil, fmt.Errorf("error opening remote zipped file %s: %v", f.Name, err)
				}
				defer rc.Close()

				var p *mpb.Progress
				if progress {
					// setup progress bar
					var total = int64(f.UncompressedSize64)
					p = mpb.New(
						mpb.WithWidth(60),
						mpb.WithRefreshRate(180*time.Millisecond),
					)
					bar := p.New(total,
						mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding("-").Rbound("|"),
						mpb.PrependDecorators(
							decor.CountersKibiByte("\t% .2f / % .2f"),
						),
						mpb.AppendDecorators(
							decor.OnComplete(decor.AverageETA(decor.ET_STYLE_GO), "✅ "),
							decor.Name(" ] "),
							decor.AverageSpeed(decor.SizeB1024(0), "% .2f", decor.WCSyncWidth),
						),
					)
					// create proxy reader
					r = bar.ProxyReader(io.LimitReader(rc, total))
					defer r.Close()
				} else {
					r = rc
				}

				Indent(log.Debug, 2)(fmt.Sprintf("Extracting %s", strings.TrimPrefix(fname, cwd)))
				out, err := os.Create(fname)
				if err != nil {
					return nil, fmt.Errorf("error creating remote unzipped file destination %s: %v", fname, err)
				}
				defer out.Close()

				io.Copy(out, r)

				if progress {
					// wait for our bar to complete and flush and close remote zip and temp file
					p.Wait()
				}

				artifacts = append(artifacts, fname)
			} else {
				Indent(log.Warn, 2)(fmt.Sprintf("%s already exists", fname))
				artifacts = append(artifacts, fname)
			}
		}
	}

	if !found {
		return nil, fmt.Errorf("no files found matching %s", pattern.String())
	}

	return artifacts, nil
}

// SearchPartialZip searches for files in a zip.Reader and returns a byte slice of the file
func SearchPartialZip(files []*zip.File, pattern *regexp.Regexp, folder string, size int64, flat, progress bool) ([]string, error) {
	var fname string
	var artifacts []string

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %v", err)
	}

	found := false
	for _, f := range files {
		if pattern.MatchString(f.Name) {
			if f.FileInfo().IsDir() {
				continue
			}
			found = true
			if flat {
				fname = filepath.Join(folder, filepath.Base(f.Name))
			} else {
				fname = filepath.Join(folder, filepath.Clean(f.Name))
			}

			if err := os.MkdirAll(filepath.Dir(fname), 0750); err != nil {
				return nil, fmt.Errorf("failed to create directory %s: %v", filepath.Dir(fname), err)
			}

			var r io.ReadCloser
			if _, err := os.Stat(fname); os.IsNotExist(err) {
				rc, err := f.Open()
				if err != nil {
					return nil, fmt.Errorf("error opening remote zipped file %s: %v", f.Name, err)
				}
				defer rc.Close()

				var p *mpb.Progress
				if progress {
					// setup progress bar
					var total = int64(size)
					p = mpb.New(
						mpb.WithWidth(60),
						mpb.WithRefreshRate(180*time.Millisecond),
					)
					bar := p.New(total,
						mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding("-").Rbound("|"),
						mpb.PrependDecorators(
							decor.CountersKibiByte("\t% .2f / % .2f"),
						),
						mpb.AppendDecorators(
							decor.OnComplete(decor.AverageETA(decor.ET_STYLE_GO), "✅ "),
							decor.Name(" ] "),
							decor.AverageSpeed(decor.SizeB1024(0), "% .2f", decor.WCSyncWidth),
						),
					)
					// create proxy reader
					r = bar.ProxyReader(io.LimitReader(rc, total))
					defer r.Close()
				} else {
					r = rc
				}

				Indent(log.Debug, 2)(fmt.Sprintf("Extracting %#x bytes of %s", size, strings.TrimPrefix(fname, cwd)))
				out, err := os.Create(fname)
				if err != nil {
					return nil, fmt.Errorf("error creating remote unzipped file destination %s: %v", fname, err)
				}
				defer out.Close()

				io.CopyN(out, r, size)

				if progress {
					// wait for our bar to complete and flush and close remote zip and temp file
					p.Wait()
				}

				artifacts = append(artifacts, fname)
			} else {
				Indent(log.Warn, 2)(fmt.Sprintf("%s already exists", fname))
				artifacts = append(artifacts, fname)
			}
		}
	}

	if !found {
		return nil, fmt.Errorf("no files found matching %s", pattern.String())
	}

	return artifacts, nil
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

	os.MkdirAll(dest, 0750)

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

		path := filepath.Join(dest, filepath.Base(filepath.Clean(f.Name)))

		if f.FileInfo().IsDir() {
			os.MkdirAll(path, 0750)
		} else {
			// TODO: add the ability to preserve folder structure if user wants
			// os.MkdirAll(filepath.Dir(path), 0750)
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()
			Indent(log.Debug, 2)(fmt.Sprintf("Extracted %s from %s", path, filepath.Base(src)))
			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range r.File {
		if filter(f) {
			fNames = append(fNames, filepath.Join(dest, filepath.Base(filepath.Clean(f.Name))))
			err := extractAndWriteFile(f)
			if err != nil {
				return nil, err
			}
		}
	}

	return fNames, nil
}

// UnTarGz - https://stackoverflow.com/a/57640231
func UnTarGz(tarfile, destPath string) error {

	r, err := os.Open(tarfile)
	if err != nil {
		return err
	}
	uncompressedStream, err := gzip.NewReader(r)
	if err != nil {
		return err
	}

	tarReader := tar.NewReader(uncompressedStream)

	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("tarReader.Next() failed: %v", err)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(header.Name, 0755); err != nil {
				return fmt.Errorf("os.Mkdir failed: %v", err)
			}
		case tar.TypeReg:
			outFile, err := os.Create(filepath.Join(destPath, header.Name))
			if err != nil {
				return fmt.Errorf("os.Create failed: %v", err)
			}
			defer outFile.Close()
			if _, err := io.Copy(outFile, tarReader); err != nil {
				return fmt.Errorf("io.Copy failed: %v", err)
			}

		default:
			return fmt.Errorf("uknown type: %v in %s",
				header.Typeflag,
				header.Name)
		}
	}
	return nil
}

func Sha1(in string) (string, error) {
	f, err := os.Open(in)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
