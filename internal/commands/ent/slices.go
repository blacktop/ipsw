package ent

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	cstypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/go-macho/types"
	ents "github.com/blacktop/ipsw/internal/codesign/entitlements"
)

// errNotMacho marks files that are neither fat nor thin Mach-O and should be skipped silently.
var errNotMacho = errors.New("not a Mach-O file")

// fileEntitlements renders the entitlements for the Mach-O at path.
// Every slice of a universal binary is inspected so the result never depends on
// the order Apple emits slices in; see PreferredSlice for the tie-break rules.
// It returns errNotMacho for non-Mach-O files and "" for unsigned Mach-Os.
func fileEntitlements(path string, conf *Config) (string, error) {
	slices, closeSlices, err := openSlices(path)
	if err != nil {
		return "", err
	}
	defer closeSlices()

	m := PreferredSlice(path, slices)
	cs := m.CodeSignature()
	if cs == nil {
		return "", nil
	}
	return renderEntitlements(path, cs, conf.LaunchConstraints), nil
}

// openSlices returns every Mach-O slice in path (a single slice for thin files).
func openSlices(path string) ([]*macho.File, func(), error) {
	fat, err := macho.OpenFat(path)
	if err == nil {
		files := make([]*macho.File, 0, len(fat.Arches))
		for _, arch := range fat.Arches {
			files = append(files, arch.File)
		}
		return files, func() { fat.Close() }, nil
	}
	if !errors.Is(err, macho.ErrNotFat) {
		return nil, nil, errNotMacho
	}
	m, err := macho.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return []*macho.File{m}, func() { m.Close() }, nil
}

// PreferredSlice picks the slice whose entitlements represent path: ARM64e_X1,
// then ARM64_X1, then ARM64e, then other ARM64, then any other CPU.
// Equal ranks prefer the larger CPU, then full subtype (including feature bits).
// The slice list must be nonempty with unique CPU/subtype pairs, as in a FAT file.
// A warning is logged when entitlements or launch constraints disagree.
func PreferredSlice(path string, slices []*macho.File) *macho.File {
	best := slices[0]
	for _, m := range slices[1:] {
		if cmp.Or(cmp.Compare(sliceRank(m), sliceRank(best)),
			cmp.Compare(m.CPU, best.CPU), cmp.Compare(m.SubCPU, best.SubCPU)) > 0 {
			best = m
		}
	}
	want := sliceEntitlements(best)
	for _, m := range slices {
		if m != best && sliceEntitlements(m) != want {
			log.Warnf("entitlements differ between %s and %s slices of %s; using %s",
				sliceName(m), sliceName(best), path, sliceName(best))
		}
	}
	return best
}

// sliceRank orders slices by ABI preference; higher wins.
func sliceRank(m *macho.File) int {
	if m.CPU != types.CPUArm64 {
		return 0
	}
	switch {
	case m.SubCPU.HasArm64X1() && m.SubCPU.HasArm64E():
		return 4
	case m.SubCPU.HasArm64X1():
		return 3
	case m.SubCPU.HasArm64E():
		return 2
	default:
		return 1
	}
}

func sliceName(m *macho.File) string {
	return m.SubCPU.String(m.CPU)
}

type sliceEntitlementData struct {
	entitlements              string
	self, parent, responsible string
}

func sliceEntitlements(m *macho.File) sliceEntitlementData {
	cs := m.CodeSignature()
	if cs == nil {
		return sliceEntitlementData{}
	}
	raw := cs.Entitlements
	if raw == "" {
		raw = string(cs.EntitlementsDER)
	}
	return sliceEntitlementData{
		entitlements: raw,
		self:         string(cs.LaunchConstraintsSelf),
		parent:       string(cs.LaunchConstraintsParent),
		responsible:  string(cs.LaunchConstraintsResponsible),
	}
}

// renderEntitlements returns the XML entitlements (falling back to decoded DER)
// followed, when requested, by the launch constraints as JSON comments.
func renderEntitlements(path string, cs *macho.CodeSignature, withLaunchConstraints bool) string {
	var output strings.Builder
	if len(cs.Entitlements) > 0 {
		output.WriteString(cs.Entitlements)
	} else if len(cs.EntitlementsDER) > 0 {
		if decoded, err := ents.DerDecode(cs.EntitlementsDER); err == nil {
			output.WriteString(decoded)
			log.Warnf("using DER entitlements for %s", path)
		}
	}
	if !withLaunchConstraints {
		return output.String()
	}
	for _, lc := range []struct {
		label string
		data  []byte
	}{
		{"Self", cs.LaunchConstraintsSelf},
		{"Parent", cs.LaunchConstraintsParent},
		{"Responsible", cs.LaunchConstraintsResponsible},
	} {
		if len(lc.data) == 0 {
			continue
		}
		parsed, err := cstypes.ParseLaunchContraints(lc.data)
		if err != nil {
			continue
		}
		if output.Len() > 0 {
			output.WriteString("\n")
		}
		fmt.Fprintf(&output, "<!-- Launch Constraints (%s) -->\n", lc.label)
		lcdata, _ := json.MarshalIndent(parsed, "", "  ")
		output.Write(lcdata)
		output.WriteString("\n")
	}
	return output.String()
}
