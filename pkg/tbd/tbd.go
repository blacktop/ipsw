package tbd

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
)

// TBD object
type TBD struct {
	UUID     string
	Archs    []string
	Platform string
	Path     string
	Version  string
	Symbols  []string
}

// NewTBD creates a new tbd object
func NewTBD(dyldPath, imageName string) (*TBD, error) {
	var syms []string
	// get dyld
	f, err := dyld.Open(dyldPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// get image
	i := f.Image(imageName)
	if i == nil {
		return nil, fmt.Errorf("image not found")
	}
	// get macho
	m, err := i.GetMacho()
	if err != nil {
		return nil, err
	}
	defer m.Close()
	// get symbols
	for _, sym := range m.Symtab.Syms {
		if sym.Type.IsAbsoluteSym() {
			syms = append(syms, sym.Name)
		}
	}

	archs := strings.Fields(strings.ToLower(m.SubCPU.String(m.CPU)))[0]

	// TODO: add objc-classes

	return &TBD{
		// TODO: do I need uuid?
		UUID:     m.UUID().ID,
		Archs:    []string{archs},
		Platform: strings.ToLower(f.Platform.String()),
		Path:     i.Name,
		Version:  m.SourceVersion().Version,
		Symbols:  syms,
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
