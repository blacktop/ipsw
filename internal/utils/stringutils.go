package utils

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/apex/log"
)

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
			return slices.Delete(s, i, i+1)
		}
	}
	return s
}

func StrSliceAddSuffix(slice []string, suffix string) []string {
	var out []string
	for _, s := range slice {
		out = append(out, s+suffix)
	}
	return out
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

func ReadCString(r io.Reader) (string, error) {
	var bytes []byte
	for {
		b := make([]byte, 1)
		_, err := r.Read(b)
		if err != nil {
			return "", err
		}
		if b[0] == 0 {
			break
		}
		bytes = append(bytes, b[0])
	}
	return string(bytes), nil
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

// isAsciiPunctOrSpace checks if a rune is common ASCII punctuation or a space.
func isAsciiPunctOrSpace(r rune) bool {
	switch r {
	case ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
		':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~', '\n', '\r', '\t':
		return true
	default:
		return false
	}
}

// IsASCII checks if given string is ascii
func IsASCII(s string) bool {
	for _, r := range s {
		if (r > unicode.MaxASCII || !unicode.IsPrint(r)) && !isAsciiPunctOrSpace(r) {
			return false
		}
	}
	return true
}

func IsPrintable(s string) bool {
	isPrintable := true
	for _, r := range s {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			isPrintable = false
			break
		}
	}
	return isPrintable
}

// UnicodeSanitize sanitizes string to be used in Hugo URL's, allowing only
// a predefined set of special Unicode characters.
// If RemovePathAccents configuration flag is enabled, Unicode accents
// are also removed.
// Hyphens in the original input are maintained.
// Spaces will be replaced with a single hyphen, and sequential replacement hyphens will be reduced to one.
func UnicodeSanitize(s string) string {
	source := []rune(s)
	target := make([]rune, 0, len(source))
	var (
		prependHyphen bool
		wasHyphen     bool
	)

	for i, r := range source {
		isAllowed := r == '.' || r == '/' || r == '\\' || r == '_' || r == '#' || r == '+' || r == '~' || r == '-' || r == '@'
		isAllowed = isAllowed || unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r)
		isAllowed = isAllowed || (r == '%' && i+2 < len(source) && IsHex(source[i+1]) && IsHex(source[i+2]))

		if isAllowed {
			// track explicit hyphen in input; no need to add a new hyphen if
			// we just saw one.
			wasHyphen = r == '-'

			if prependHyphen {
				// if currently have a hyphen, don't prepend an extra one
				if !wasHyphen {
					target = append(target, '-')
				}
				prependHyphen = false
			}
			target = append(target, r)
		} else if len(target) > 0 && !wasHyphen && unicode.IsSpace(r) {
			prependHyphen = true
		}
	}

	return string(target)
}

func IsPunctuation(c byte) bool {
	return slices.Contains([]byte("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"), c)
}

func IsSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

func IsLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func IsAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || IsLetter(c)
}

func IsHex(c rune) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}
	return false
}

func Slugify(s string) string {
	in := []byte(s)
	if len(in) == 0 {
		return string(in)
	}
	out := make([]byte, 0, len(in))
	sym := false
	for _, ch := range in {
		if IsAlnum(ch) {
			sym = false
			out = append(out, ch)
		} else if IsPunctuation(ch) {
			sym = false
		} else if sym {
			continue
		} else {
			out = append(out, '-')
			sym = true
		}
	}
	var a, b int
	var ch byte
	for a, ch = range out {
		if ch != '-' {
			break
		}
	}
	for b = len(out) - 1; b > 0; b-- {
		if out[b] != '-' {
			break
		}
	}
	return strings.ToLower(string(out[a : b+1]))
}

func Bits(in uint64) string {
	var out strings.Builder
	out.WriteString("|63  |59  |55  |51  |47  |43  |39  |35  |31  |27  |23  |19  |15  |11  |7   |3   |\n")
	for i, b := range fmt.Sprintf("%064b", in) {
		if i%4 == 0 && i != 0 {
			out.WriteRune(' ')
		}
		out.WriteRune(b)
	}
	return out.String()
}
