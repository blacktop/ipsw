package tbd

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
)

// TBD object
type TBD struct {
	Targets     []string
	Path        string
	Symbols     []string
	ObjcClasses []string
	ObjcIvars   []string
}

// NewTBD creates a new tbd object
func NewTBD(image *dyld.CacheImage, private bool) (*TBD, error) {
	var syms []string
	var objcClasses []string
	var objcIvars []string

	m, err := image.GetMacho()
	if err != nil {
		return nil, err
	}
	defer m.Close()

	// get public symbols
	for _, sym := range m.Symtab.Syms {
		if sym.Name == "<redacted>" || sym.Value == 0 {
			continue
		}
		syms = utils.UniqueAppend(syms, sym.Name)
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
		Targets: []string{
			"x86_64-macos",
			"x86_64-maccatalyst",
			"arm64-macos",
			"arm64-maccatalyst",
			"arm64e-macos",
			"arm64e-maccatalyst",
			"armv7-ios",
			"armv7s-ios",
			"arm64-ios",
			"arm64e-ios",
		},
		Path:        image.Name,
		Symbols:     syms,
		ObjcClasses: objcClasses,
		ObjcIvars:   objcIvars,
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
