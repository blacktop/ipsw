package utils

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
	"github.com/vbauerster/mpb/v7"
	"github.com/vbauerster/mpb/v7/decor"
)

var normalPadding = cli.Default.Padding

func init() {
	rand.Seed(time.Now().Unix())
}

type stop struct {
	error
}

func Retry(attempts int, sleep time.Duration, f func() error) error {
	if err := f(); err != nil {
		if s, ok := err.(stop); ok {
			// Return the original error for later checking
			return s.error
		}

		if attempts--; attempts > 0 {
			jitter := time.Duration(rand.Int63n(int64(sleep)))
			sleep = sleep + jitter/2

			time.Sleep(sleep)
			return Retry(attempts, 2*sleep, f)
		}
		return fmt.Errorf("after %d attempts, %v", attempts, err)
	}

	return nil
}

// ConvertStrToInt converts an input string to uint64
func ConvertStrToInt(intStr string) (uint64, error) {
	intStr = strings.ToLower(intStr)

	if strings.ContainsAny(strings.ToLower(intStr), "xabcdef") {
		intStr = strings.Replace(intStr, "0x", "", -1)
		intStr = strings.Replace(intStr, "x", "", -1)
		if out, err := strconv.ParseUint(intStr, 16, 64); err == nil {
			return out, err
		}
		log.Warn("assuming given integer is in decimal")
	}
	return strconv.ParseUint(intStr, 10, 64)
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

// Pad creates left padding for printf members
func Pad(length int) string {
	if length > 0 {
		return strings.Repeat(" ", length)
	}
	return " "
}

// StrSliceContains returns true if string slice contains given string
func StrSliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.Contains(strings.ToLower(s), strings.ToLower(item)) {
			return true
		}
	}
	return false
}

// StrContainsStrSliceItem returns true if given string contains any item in the string slice
func StrContainsStrSliceItem(item string, slice []string) bool {
	for _, s := range slice {
		if strings.Contains(strings.ToLower(item), strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// StrSliceHas returns true if string slice has an exact given string
func StrSliceHas(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(strings.ToLower(item), strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// FilterStrSlice removes all the strings that do NOT contain the filter from a string slice
func FilterStrSlice(slice []string, filter string) []string {
	var filtered []string
	for _, s := range slice {
		if strings.Contains(strings.ToLower(s), strings.ToLower(filter)) {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// FilterStrFromSlice removes all the strings that contain the filter from a string slice
func FilterStrFromSlice(slice []string, filter string) []string {
	var filtered []string
	for _, s := range slice {
		if !strings.Contains(strings.ToLower(s), strings.ToLower(filter)) {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// TrimPrefixStrSlice trims the prefix from all strings in string slice
func TrimPrefixStrSlice(slice []string, prefix string) []string {
	var trimmed []string
	for _, s := range slice {
		trimmed = append(trimmed, strings.TrimPrefix(s, prefix))
	}
	return trimmed
}

// RemoveStrFromSlice removes a single string from a string slice
func RemoveStrFromSlice(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

// Uint64SliceContains returns true if uint64 slice contains given uint64
func Uint64SliceContains(slice []uint64, item uint64) bool {
	for _, s := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func StrSliceAddSuffix(slice []string, suffix string) []string {
	var out []string
	for _, s := range slice {
		out = append(out, s+suffix)
	}
	return out
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
	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}

func UniqueConcat[T comparable](slice []T, in []T) []T {
	for _, i := range in {
		for _, ele := range slice {
			if ele == i {
				return slice
			}
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
	for i := 0; i < len(ts); i++ {
		pairs[i] = Pair[T, U]{ts[i], us[i]}
	}
	return pairs, nil
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

// RemoteUnzip unzips a remote file from zip (like partialzip)
func RemoteUnzip(files []*zip.File, pattern *regexp.Regexp, folder string, flat, progress bool) error {
	var fname string

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %v", err)
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
				return fmt.Errorf("failed to create directory %s: %v", filepath.Dir(fname), err)
			}

			var r io.ReadCloser
			if _, err := os.Stat(fname); os.IsNotExist(err) {
				rc, err := f.Open()
				if err != nil {
					return fmt.Errorf("error opening remote zipped file %s: %v", f.Name, err)
				}
				defer rc.Close()

				var p *mpb.Progress
				if progress {
					// setup progress bar
					var total int64 = int64(f.UncompressedSize64)
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
							decor.AverageSpeed(decor.UnitKiB, "% .2f"),
						),
					)
					// create proxy reader
					r = bar.ProxyReader(io.LimitReader(rc, total))
					defer r.Close()
				} else {
					r = rc
				}

				Indent(log.Info, 2)(fmt.Sprintf("Extracting %s", strings.TrimPrefix(fname, cwd)))
				out, err := os.Create(fname)
				if err != nil {
					return fmt.Errorf("error creating remote unzipped file destination %s: %v", fname, err)
				}
				defer out.Close()

				io.Copy(out, r)

				if progress {
					// wait for our bar to complete and flush and close remote zip and temp file
					p.Wait()
				}

			} else {
				Indent(log.Warn, 2)(fmt.Sprintf("%s already exists", fname))
			}
		}
	}

	if !found {
		return fmt.Errorf("no files found matching %s", pattern.String())
	}

	return nil
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
			fNames = append(fNames, filepath.Base(filepath.Clean(f.Name)))
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

// GrepStrings returns all matching strings in []byte
func GrepStrings(data []byte, searchStr string) []string {

	var matchStrings []string

	r := bytes.NewBuffer(data[:])

	for {
		s, err := r.ReadString('\x00')

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatal(err.Error())
		}

		if len(s) > 0 && strings.Contains(s, searchStr) {
			matchStrings = append(matchStrings, strings.Trim(s, "\x00"))
		}
	}

	return matchStrings
}

// IsASCII checks if given string is ascii
func IsASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
