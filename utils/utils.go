package utils

import (
	"crypto/sha1"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
)

var (
	normalPadding    = cli.Default.Padding
	doublePadding    = normalPadding * 2
	triplePadding    = normalPadding * 3
	quadruplePadding = normalPadding * 4
)

// Indent indents apex log line
func Indent(f func(s string)) func(string) {
	return func(s string) {
		cli.Default.Padding = doublePadding
		f(s)
		cli.Default.Padding = normalPadding
	}
}

// DoubleIndent double indents apex log line
func DoubleIndent(f func(s string)) func(string) {
	return func(s string) {
		cli.Default.Padding = triplePadding
		f(s)
		cli.Default.Padding = normalPadding
	}
}

// TripleIndent triple indents apex log line
func TripleIndent(f func(s string)) func(string) {
	return func(s string) {
		cli.Default.Padding = quadruplePadding
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
	Indent(log.Info)("verifying sha1sum...")
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
	}).Debug)("sha1 hashes")
	return strings.EqualFold(sha1sum, fmt.Sprintf("%x", h.Sum(nil))), nil
}
