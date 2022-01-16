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
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
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

		path := filepath.Join(dest, filepath.Base(f.Name))

		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
		} else {
			// TODO: add the ability to preserve folder structure if user wants
			// os.MkdirAll(filepath.Dir(path), f.Mode())
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()
			Indent(log.Info, 2)(fmt.Sprintf("Created %s", path))
			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range r.File {
		if filter(f) {
			fNames = append(fNames, filepath.Base(f.Name))
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

	for true {
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
