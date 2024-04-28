package tbd

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
)

var macOs32bitTargets = []string{"i386-macos"}
var macOs64bitIntelTargets = []string{"x86_64-macos", "x86_64h-macos"}
var macOs64bitArmTargets = []string{"arm64-macos", "arm64e-macos"}
var macCatalyst32bitTargets = []string{"i386-maccatalyst"}
var macCatalyst64bitIntelTargets = []string{"x86_64-maccatalyst", "x86_64h-maccatalyst"}
var macCatalyst64bitArmTargets = []string{"arm64-maccatalyst", "arm64e-maccatalyst"}
var iOS32bitTargets = []string{"armv7-ios", "armv7s-ios"}
var iOS64bitTargets = []string{"arm64-ios", "arm64e-ios"}

// TBD object
type TBD struct {
	Targets        []string
	Path           string
	CurrentVersion string
	Umbrella       string
	ReExports      []string
	Symbols        []string
	ObjcClasses    []string
	ObjcIvars      []string
}

// NewTBD creates a new tbd object
func NewTBD(image *dyld.CacheImage, reexports []string, private, generic bool) (*TBD, error) {
	var targets []string
	var currentVersion string
	var syms []string
	var objcClasses []string
	var objcIvars []string
	var umbrella string

	m, err := image.GetMacho()
	if err != nil {
		return nil, err
	}
	defer m.Close()

	if generic {
		targets = append(targets, macOs32bitTargets...)
		targets = append(targets, macCatalyst32bitTargets...)
		targets = append(targets, macOs64bitIntelTargets...)
		targets = append(targets, macCatalyst64bitIntelTargets...)
		targets = append(targets, macOs64bitArmTargets...)
		targets = append(targets, macCatalyst64bitArmTargets...)
		targets = append(targets, iOS32bitTargets...)
		targets = append(targets, iOS64bitTargets...)
	} else {
		if bvs := m.BuildVersions(); len(bvs) > 0 {
			for _, bv := range bvs {
				switch bv.Platform {
				case types.Platform_macOS:
					if m.FileHeader.Magic == types.Magic64 {
						if m.CPU == types.CPUAmd64 {
							targets = append(targets, macOs64bitIntelTargets...)
						} else {
							targets = append(targets, macOs64bitArmTargets...)
						}
					} else {
						targets = append(targets, macOs32bitTargets...)
					}
				case types.Platform_iOS:
					if m.FileHeader.Magic == types.Magic64 {
						targets = append(targets, iOS64bitTargets...)
					} else {
						targets = append(targets, iOS32bitTargets...)
					}
				case types.Platform_macCatalyst:
					if m.FileHeader.Magic == types.Magic64 {
						if m.CPU == types.CPUAmd64 {
							targets = append(targets, macCatalyst64bitIntelTargets...)
						} else {
							targets = append(targets, macCatalyst64bitArmTargets...)
						}
					} else {
						targets = append(targets, macCatalyst32bitTargets...)
					}
				}
			}
		} else {
			targets = append(targets, macOs32bitTargets...)
			targets = append(targets, macCatalyst32bitTargets...)
			targets = append(targets, macOs64bitIntelTargets...)
			targets = append(targets, macCatalyst64bitIntelTargets...)
			targets = append(targets, macOs64bitArmTargets...)
			targets = append(targets, macCatalyst64bitArmTargets...)
			targets = append(targets, iOS32bitTargets...)
			targets = append(targets, iOS64bitTargets...)
		}
	}

	// get current version
	if id := m.DylibID(); id != nil {
		currentVersion = id.CurrentVersion.String()
	}

	// get umbrella
	for _, l := range m.Loads {
		if s, ok := l.(*macho.SubFramework); ok {
			umbrella = s.String()
			break
		}
	}

	// TODO: what other fields are there?

	// get public symbols
	for _, sym := range m.Symtab.Syms {
		if sym.Name == "<redacted>" || sym.Value == 0 {
			continue
		}
		if sym.Type.IsExternalSym() {
			syms = utils.UniqueAppend(syms, sym.Name)
		}
	}
	if exports, err := m.DyldExports(); err == nil {
		for _, export := range exports {
			syms = utils.UniqueAppend(syms, export.Name)
		}
	}
	if exports, err := m.GetExports(); err == nil {
		for _, export := range exports {
			syms = utils.UniqueAppend(syms, export.Name)
		}
	}

	// get private symbols
	if private {
		if err := image.ParseLocalSymbols(false); err != nil {
			return nil, err
		}
		for _, sym := range image.LocalSymbols {
			syms = append(syms, sym.Name)
		}
	}

	// get objc classes and ivars
	if m.HasObjC() {
		classes, err := m.GetObjCClasses()
		if err != nil {
			return nil, err
		}
		for _, class := range classes {
			objcClasses = append(objcClasses, class.Name)
			for _, ivar := range class.Ivars {
				objcIvars = append(objcIvars, fmt.Sprintf("%s.%s", class.Name, ivar.Name))
			}
		}
	}

	sort.Strings(syms)
	sort.Strings(objcClasses)
	sort.Strings(objcIvars)

	return &TBD{
		Targets:        targets,
		Path:           image.Name,
		CurrentVersion: currentVersion,
		Umbrella:       umbrella,
		ReExports:      reexports,
		Symbols:        syms,
		ObjcClasses:    objcClasses,
		ObjcIvars:      objcIvars,
	}, nil
}

// Generate generates a tbd file from a template
func (t *TBD) Generate() (string, error) {
	var tplOut bytes.Buffer

	tmpl := template.Must(template.New("tbd").Funcs(template.FuncMap{"StringsJoin": strings.Join}).Parse(tbdTemplate))

	err := tmpl.Execute(&tplOut, t)
	if err != nil {
		return "", errors.Wrap(err, "failed to execute template")
	}

	return tplOut.String(), nil
}
