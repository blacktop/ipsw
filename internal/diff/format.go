package diff

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/ast"
	"github.com/gomarkdown/markdown/html"
)

// {{ range $index, $element := .Ents }}
// 		- [{{ $element }}](#{{ $element | urlize }})
// {{ end -}}

const diffMarkdownTemplate = `
- [{{ .Title }}](#{{ .Title | slug }})
	- [IPSWs](#ipsws)
	- [Kernel](#kernel)
		- [Version](#version)
		- [Kexts](#kexts)
{{- if .Kexts.New }}
			- [🆕 NEW ({{ len .Kexts.New }})](#-new)
{{- end }}
{{- if .Kexts.Removed }}
			- [❌ Removed ({{ len .Kexts.Removed }})](#-removed)
{{- end }}
{{- if .Kexts.Updated }}
			- [⬆️ Updated ({{ len .Kexts.Updated }})](#️-updated)
{{- end }}		
	- [Machos](#machos)
{{- if .Machos }}	
{{- if .Machos.New }}
		- [🆕 NEW ({{ len .Machos.New }})](#-new-1)
{{- end }}
{{- if .Machos.Removed }}
		- [❌ Removed ({{ len .Machos.Removed }})](#-removed-1)
{{- end }}
{{- if .Machos.Updated }}
		- [⬆️ Updated ({{ len .Machos.Updated }})](#️-updated-1)
{{- end }}
{{- end }}
{{- if .Ents }}
		- [Entitlements](#entitlements)
{{- end }}
	- [DSC](#dsc)
		- [WebKit](#webkit)
		- [Dylibs](#dylibs)
{{- if .Dylibs }}			
{{- if .Dylibs.New }}
			- [🆕 NEW ({{ len .Dylibs.New }})](#-new-2)
{{- end }}
{{- if .Dylibs.Removed }}
			- [❌ Removed ({{ len .Dylibs.Removed }})](#️-removed-2)
{{- end }}
{{- if .Dylibs.Updated }}
			- [⬆️ Updated ({{ len .Dylibs.Updated }})](#️-updated-2)
{{- end }}
{{- end }}


# {{ .Title }}

## IPSWs

- {{ .Old.IPSWPath | base }}
- {{ .New.IPSWPath | base }}

## Kernel

### Version

| iOS                                     | Version                                 | Build                                | Date                                  |
| :-------------------------------------- | :-------------------------------------- | :----------------------------------- | :------------------------------------ |
| {{ .Old.Version }} *({{ .Old.Build }})* | {{ .Old.Kernel.Version.KernelVersion.Darwin }} | {{ .Old.Kernel.Version.KernelVersion.XNU }} | {{ .Old.Kernel.Version.KernelVersion.Date.Format "Mon, 02Jan2006 15:04:05 MST" }} |
| {{ .New.Version }} *({{ .New.Build }})* | {{ .New.Kernel.Version.KernelVersion.Darwin }} | {{ .New.Kernel.Version.KernelVersion.XNU }} | {{ .New.Kernel.Version.KernelVersion.Date.Format "Mon, 02Jan2006 15:04:05 MST" }} |

### Kexts
{{ if .Kexts.New }}
### 🆕 NEW
{{ range .Kexts.New }}
- {{ . | code }}
{{ end }}
{{ end -}}
{{- if .Kexts.Removed }}
### ❌ Removed
{{ range .Kexts.Removed }}
- {{ . | code }}
{{ end }}
{{ end -}}
{{- if .Kexts.Updated }}
### ⬆️ Updated
<details>
  <summary><i>View Updated</i></summary>

{{ range $key, $value := .Kexts.Updated }}
#### {{ $key | base }}
> {{ $key | code }}
{{ $value | noescape }}
{{ end }}

</details>
{{ end -}}

{{ if .KDKs }}
## KDKs
- {{ .Old.KDK | code}}
- {{ .New.KDK | code}}

{{ .KDKs | noescape }}
{{end -}}

{{- if .Machos }}
## MachOs
{{ if .Machos.New }}
### 🆕 NEW
{{ range .Machos.New }}
- {{ . | code }}
{{ end }}
{{ end -}}
{{- if .Machos.Removed }}
### ❌ Removed
{{ range .Machos.Removed }}
- {{ . | code }}
{{ end }}
{{ end -}}
{{- if .Machos.Updated }}
### ⬆️ Updated
<details>
  <summary><i>View Updated</i></summary>

{{ range $key, $value := .Machos.Updated }}
#### {{ $key | base }}
> {{ $key | code }}
{{ $value | noescape }}
{{ end }}

</details>
{{ end -}}
{{ end -}}
{{ if .Ents }}
### Entitlements
<details>
  <summary><i>View Entitlements</i></summary>

  {{ .Ents | noescape }}

</details>
{{ end -}}
{{ if .Launchd }}
## launchd Config
{{ .Launchd | noescape }}
{{ end }}

## DSC

### WebKit

| iOS                                     | Version           |
| :-------------------------------------- | :---------------- |
| {{ .Old.Version }} *({{ .Old.Build }})* | {{ .Old.Webkit }} |
| {{ .New.Version }} *({{ .New.Build }})* | {{ .New.Webkit }} |

{{- if .Dylibs }}
### Dylibs
{{ if .Dylibs.New }}
#### 🆕 NEW
{{ range .Dylibs.New }}
- {{ . | code }}
{{ end }}
{{ end -}}
{{- if .Dylibs.Removed }}
#### ❌ Removed
{{ range .Dylibs.Removed }}
- {{ . | code }}
{{ end }}
{{ end -}}
{{- if .Dylibs.Updated }}
#### ⬆️ Updated
<details>
  <summary><i>View Updated</i></summary>

{{ range $key, $value := .Dylibs.Updated }}
##### {{ $key | base }}
> {{ $key | code }}
{{ $value | noescape }}
{{ end }}

</details>
{{ end -}}
{{ end -}}
`

func (d *Diff) String() string {
	var tmptout bytes.Buffer

	tmpl := template.Must(template.New("diff").
		Funcs(template.FuncMap{
			"noescape": func(value interface{}) template.HTML {
				return template.HTML(fmt.Sprint(value))
			},
		}).
		Funcs(template.FuncMap{
			"base": func(value string) template.HTML {
				return template.HTML(fmt.Sprintf("`%s`", filepath.Base(value)))
			},
		}).
		Funcs(template.FuncMap{
			"code": func(value string) template.HTML {
				return template.HTML(fmt.Sprintf("`%s`", value))
			},
		}).
		Funcs(template.FuncMap{
			"slug": func(value string) string {
				return utils.Slugify(value)
			},
		}).
		Parse(diffMarkdownTemplate))
	if err := tmpl.Execute(&tmptout, d); err != nil {
		return fmt.Errorf("failed to execute diff template: %s", err).Error()
	}

	return tmptout.String()
}

func (d *Diff) ToHTML(folder string) error {
	htmlHeader := `<!DOCTYPE html>
<html lang="en">
<head>
   <meta charset="UTF-8">
   <meta http-equiv="X-UA-Compatible" content="IE=edge">
   <meta name="viewport" content="width=device-width, initial-scale=1.0">
   <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.3/css/bulma.min.css">
</head>
<body>
<br>
<div class="container is-max-desktop">
<div class="content">`

	htmlFooter := `
</div>
</div>
<br>
</body>
</html>
`
	var htmlBuf bytes.Buffer

	renderer := html.NewRenderer(html.RendererOptions{
		Title:          d.Title,
		Flags:          html.TOC | html.CommonFlags,
		RenderNodeHook: renderHook,
	})
	output := string(markdown.ToHTML([]byte(d.String()), nil, renderer))

	tmpl := template.Must(template.New("Render").Parse(htmlHeader + "{{.}}" + htmlFooter))
	if err := tmpl.Execute(&htmlBuf, template.HTML(output)); err != nil {
		return err
	}

	if err := os.MkdirAll(folder, 0755); err != nil {
		return err
	}

	fname := filepath.Join(folder, fmt.Sprintf("%s.html", d.Title))
	log.Infof("Creating HTML diff file: %s", fname)
	return os.WriteFile(fname, htmlBuf.Bytes(), 0644)
}

func renderHook(w io.Writer, node ast.Node, entering bool) (ast.WalkStatus, bool) {
	if _, ok := node.(*ast.Heading); ok {
		level := strconv.Itoa(node.(*ast.Heading).Level)

		if entering && level == "1" {
			w.Write([]byte(`<h1 class="title is-1 has-text-centered">`))
		} else if entering {
			w.Write([]byte("<h" + level + ">"))
		} else {
			w.Write([]byte("</h" + level + ">"))
		}

		return ast.GoToNext, true

	} else if _, ok := node.(*ast.Image); ok {
		src := string(node.(*ast.Image).Destination)

		c := node.(*ast.Image).GetChildren()[0]
		alt := string(c.AsLeaf().Literal)

		if entering && alt != "" {
			w.Write([]byte(`<figure class="image is-5by3"><img src="` + src + `" alt="` + alt + `">`))
		} else if entering {
			w.Write([]byte(`<figure class="image is-5by3"><img src="` + src + `">`))
		} else {
			w.Write([]byte(`</figure>`))
		}

		return ast.SkipChildren, true
	} else {
		return ast.GoToNext, false
	}
}

// func (c *Context) MarshalJSON() ([]byte, error) {
// 	return json.Marshal(&struct {
// 		ID       int         `json:"id,omitempty"`
// 		Name     string      `json:"name,omitempty"`
// 		Info     info        `json:"info,omitempty"`
// 		Encoding intEncoding `json:"encoding,omitempty"`
// 	}{
// 		ID:       i.id,
// 		Name:     i.name,
// 		Info:     i.info,
// 		Encoding: i.encoding,
// 	})
// }
