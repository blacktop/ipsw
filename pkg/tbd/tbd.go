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
	UUIDs    []string
	Archs    []string
	Platform string
	Path     string
	Version  string
	Symbols  []string
}

// NewTBD creates a new tbd object
func NewTBD(f *dyld.File, image *dyld.CacheImage) (*TBD, error) {
	var syms []string

	m, err := image.GetMacho()
	if err != nil {
		return nil, err
	}
	defer m.Close()

	// get symbols
	if m.DyldExportsTrie() != nil && m.DyldExportsTrie().Size > 0 {
		exports, err := m.DyldExports()
		if err != nil {
			return nil, err
		}
		for _, sym := range exports {
			syms = append(syms, sym.Name)
		}
	} else {
		return nil, fmt.Errorf("%s contains no exported symbols", image.Name)
	}

	arch := strings.Fields(strings.ToLower(m.SubCPU.String(m.CPU)))[0]
	uuid := fmt.Sprintf("'%s: %s'", arch, m.UUID().UUID.String())
	// TODO: add objc-classes

	return &TBD{
		UUIDs:    []string{uuid},
		Archs:    []string{arch},
		Platform: strings.ToLower(f.Headers[f.UUID].Platform.String()),
		Path:     image.Name,
		Version:  m.SourceVersion().Version.String(),
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
