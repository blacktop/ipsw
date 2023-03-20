package diff

import (
	"bytes"
	"fmt"
	"html/template"
)

const diffMarkdownTemplate = `
# {{ .Title }}

## Kernel

### Version

| iOS                                     | Version                                 | Build                                | Date                                  |
| :-------------------------------------- | :-------------------------------------- | :----------------------------------- | :------------------------------------ |
| {{ .Old.Version }} *({{ .Old.Build }})* | {{ .Old.Kernel.Version.Kernel.Darwin }} | {{ .Old.Kernel.Version.Kernel.XNU }} | {{ .Old.Kernel.Version.Kernel.Date.Format "Mon, 02Jan2006 15:04:05 MST" }} |
| {{ .New.Version }} *({{ .New.Build }})* | {{ .New.Kernel.Version.Kernel.Darwin }} | {{ .New.Kernel.Version.Kernel.XNU }} | {{ .New.Kernel.Version.Kernel.Date.Format "Mon, 02Jan2006 15:04:05 MST" }} |

### Kexts

{{ .Kexts }}

## Entitlements

{{ .Ents }}

## DSC

### WebKit

| iOS                                     | Version           |
| :-------------------------------------- | :---------------- |
| {{ .Old.Version }} *({{ .Old.Build }})* | {{ .Old.Webkit }} |
| {{ .New.Version }} *({{ .New.Build }})* | {{ .New.Webkit }} |

{{ .Dylibs }}
`

func (d *Diff) String() string {
	var tmptout bytes.Buffer

	tmpl := template.Must(template.New("diff").Parse(diffMarkdownTemplate))
	if err := tmpl.Execute(&tmptout, d); err != nil {
		return fmt.Errorf("failed to execute diff template: %s", err).Error()
	}

	return tmptout.String()
}
