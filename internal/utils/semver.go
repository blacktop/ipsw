package utils

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type parsed struct {
	major string
	minor string
	patch string
	short string
	micro string
}

func DiffVersion(v, w string) (string, error) {
	pv, ok1 := parse(v)
	pw, ok2 := parse(w)
	if !ok1 && !ok2 {
		return "", fmt.Errorf("invalid versions: %q, %q", v, w)
	}
	if !ok1 {
		return "", fmt.Errorf("invalid version: %q", v)
	}
	if !ok2 {
		return "", fmt.Errorf("invalid version: %q", w)
	}
	pvm, err := strconv.Atoi(pv.major)
	if err != nil {
		return "", err
	}
	pwm, err := strconv.Atoi(pw.major)
	if err != nil {
		return "", err
	}
	pmdelta := max(pvm-pwm, 0)
	pvn, err := strconv.Atoi(pv.minor)
	if err != nil {
		return "", err
	}
	pwn, err := strconv.Atoi(pw.minor)
	if err != nil {
		return "", err
	}
	pndelta := max(pvn-pwn, 0)
	pvp, err := strconv.Atoi(pv.patch)
	if err != nil {
		return "", err
	}
	pwp, err := strconv.Atoi(pw.patch)
	if err != nil {
		return "", err
	}
	ppdelta := max(pvp-pwp, 0)
	pvs, err := strconv.Atoi(pv.short)
	if err != nil {
		return "", err
	}
	pws, err := strconv.Atoi(pw.short)
	if err != nil {
		return "", err
	}
	psdelta := max(pvs-pws, 0)
	pvc, err := strconv.Atoi(pv.micro)
	if err != nil {
		return "", err
	}
	pwc, err := strconv.Atoi(pw.micro)
	if err != nil {
		return "", err
	}
	pcdelta := max(pvc-pwc, 0)
	return fmt.Sprintf("%d.%d.%d.%d.%d", pmdelta, pndelta, ppdelta, psdelta, pcdelta), nil
}

// Compare returns an integer comparing two versions according to
// semantic version precedence.
// The result will be 0 if v == w, -1 if v < w, or +1 if v > w.
//
// An invalid semantic version string is considered less than a valid one.
// All invalid semantic version strings compare equal to each other.
func Compare(v, w string) int {
	pv, ok1 := parse(v)
	pw, ok2 := parse(w)
	if !ok1 && !ok2 {
		return 0
	}
	if !ok1 {
		return -1
	}
	if !ok2 {
		return +1
	}
	if c := compareInt(pv.major, pw.major); c != 0 {
		return c
	}
	if c := compareInt(pv.minor, pw.minor); c != 0 {
		return c
	}
	if c := compareInt(pv.patch, pw.patch); c != 0 {
		return c
	}
	if c := compareInt(pv.short, pw.short); c != 0 {
		return c
	}
	if c := compareInt(pv.micro, pw.micro); c != 0 {
		return c
	}
	return 0
}

// ByVersion implements sort.Interface for sorting semantic version strings.
type ByVersion []string

func (vs ByVersion) Len() int      { return len(vs) }
func (vs ByVersion) Swap(i, j int) { vs[i], vs[j] = vs[j], vs[i] }
func (vs ByVersion) Less(i, j int) bool {
	cmp := Compare(vs[i], vs[j])
	if cmp != 0 {
		return cmp < 0
	}
	return vs[i] < vs[j]
}

// SortVersions sorts a list of semantic version strings using ByVersion.
func SortVersions(list []string) {
	sort.Sort(ByVersion(list))
}

type MachoVersion struct {
	Name    string
	Version string
}

type ByMachoVersion []MachoVersion

func (vs ByMachoVersion) Len() int      { return len(vs) }
func (vs ByMachoVersion) Swap(i, j int) { vs[i], vs[j] = vs[j], vs[i] }
func (vs ByMachoVersion) Less(i, j int) bool {
	cmp := Compare(vs[i].Version, vs[j].Version)
	if cmp != 0 {
		return cmp > 0
	}
	return strings.Compare(vs[i].Name, vs[j].Name) < 0
}

func SortMachoVersions(list []MachoVersion) {
	sort.Sort(ByMachoVersion(list))
}

func parse(v string) (p parsed, ok bool) {
	p.major, v, ok = parseInt(v)
	if !ok {
		return
	}
	if v == "" {
		p.minor = "0"
		p.patch = "0"
		p.short = ".0.0"
		return
	}
	if v[0] != '.' {
		ok = false
		return
	}
	p.minor, v, ok = parseInt(v[1:])
	if !ok {
		return
	}
	if v == "" {
		p.patch = "0"
		p.short = ".0"
		return
	}
	if v[0] != '.' {
		ok = false
		return
	}
	p.patch, v, ok = parseInt(v[1:])
	if !ok {
		return
	}
	if v == "" {
		p.patch = "0"
		p.short = ".0"
		return
	}
	if v[0] != '.' {
		ok = false
		return
	}
	p.short, v, ok = parseInt(v[1:])
	if !ok {
		return
	}
	if v == "" {
		p.short = ".0"
		return
	}
	if v[0] != '.' {
		ok = false
		return
	}
	p.micro, v, ok = parseInt(v[1:])
	if !ok {
		return
	}
	if v != "" {
		ok = false
		return
	}
	ok = true
	return
}

func parseInt(v string) (t, rest string, ok bool) {
	if v == "" {
		return
	}
	if v[0] < '0' || '9' < v[0] {
		return
	}
	i := 1
	for i < len(v) && '0' <= v[i] && v[i] <= '9' {
		i++
	}
	if v[0] == '0' && i != 1 {
		return
	}
	return v[:i], v[i:], true
}

func compareInt(x, y string) int {
	if x == y {
		return 0
	}
	if len(x) < len(y) {
		return -1
	}
	if len(x) > len(y) {
		return +1
	}
	if x < y {
		return -1
	} else {
		return +1
	}
}
