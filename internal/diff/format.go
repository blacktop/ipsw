package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/apex/log"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/gomarkdown/markdown"
	mdhtml "github.com/gomarkdown/markdown/html"
)

// {{ range $index, $element := .Ents }}
// 		- [{{ $element }}](#{{ $element | urlize }})
// {{ end -}}

const diffMarkdownTemplate = `
- [{{ .Title }}](#{{ .Title | slug }})
	- [Inputs](#inputs)
	- [Kernel](#kernel)
		- [Version](#version)
{{- if .Kexts }}
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
		- [🔑 Entitlements](#entitlements)
{{- end }}
{{- if .Sandbox }}
		- [Sandbox Profiles](#sandbox-profiles)
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

## Inputs

- {{ .Old.IPSWPath | base }}
- {{ .New.IPSWPath | base }}

## Kernel
{{ if .Old.Kernel.Version }}
### Version

| iOS                                     | Version                                 | Build                                | Date                                  |
| :-------------------------------------- | :-------------------------------------- | :----------------------------------- | :------------------------------------ |
| {{ .Old.Version }} *({{ .Old.Build }})* | {{ .Old.Kernel.Version.KernelVersion.Darwin }} | {{ .Old.Kernel.Version.KernelVersion.XNU }} | {{ .Old.Kernel.Version.KernelVersion.Date.Format "Mon, 02Jan2006 15:04:05 MST" }} |
| {{ .New.Version }} *({{ .New.Build }})* | {{ .New.Kernel.Version.KernelVersion.Darwin }} | {{ .New.Kernel.Version.KernelVersion.XNU }} | {{ .New.Kernel.Version.KernelVersion.Date.Format "Mon, 02Jan2006 15:04:05 MST" }} |
{{ end -}}
{{ if .Kexts }}
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
{{ end -}}
{{ if .KDKs }}
## KDKs
- {{ .Old.KDK | code}}
- {{ .New.KDK | code}}

{{ .KDKs | noescape }}
{{ end -}}

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
### 🔑 Entitlements
<details>
  <summary><i>View Entitlements</i></summary>

  {{ .Ents | noescape }}

</details>
{{ end -}}

{{ if .Sandbox }}
## Sandbox Profiles
{{ .Sandbox | noescape }}
{{ end -}}

{{- if .Firmwares }}
## Firmwares
{{ if .Firmwares.New }}
### 🆕 NEW
{{ range .Firmwares.New }}
- {{ . | code }}
{{ end }}
{{ end -}}
{{- if .Firmwares.Removed }}
### ❌ Removed
{{ range .Firmwares.Removed }}
- {{ . | code }}
{{ end }}
{{ end -}}
{{- if .Firmwares.Updated }}
### ⬆️ Updated
<details>
  <summary><i>View Updated</i></summary>

{{ range $key, $value := .Firmwares.Updated }}
#### {{ $key | base }}
> {{ $key | code }}
{{ $value | noescape }}
{{ end }}

</details>
{{ end -}}
{{ end -}}

{{ if .Launchd }}
## launchd Config
{{ .Launchd | noescape }}
{{ end }}

## DSC

{{ if .Old.Webkit }}
### WebKit

| iOS                                     | Version           |
| :-------------------------------------- | :---------------- |
| {{ .Old.Version }} *({{ .Old.Build }})* | {{ .Old.Webkit }} |
| {{ .New.Version }} *({{ .New.Build }})* | {{ .New.Webkit }} |
{{ end -}}
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

var diffMDTmpl = template.Must(template.New("diff").
	Funcs(template.FuncMap{
		"noescape": func(value any) template.HTML {
			return template.HTML(fmt.Sprint(value))
		},
		"base": func(value string) template.HTML {
			return template.HTML(fmt.Sprintf("`%s`", filepath.Base(value)))
		},
		"code": func(value string) template.HTML {
			return template.HTML(fmt.Sprintf("`%s`", value))
		},
		"slug": func(value string) string {
			return utils.Slugify(value)
		},
	}).
	Parse(diffMarkdownTemplate))

var diffHTMLTmpl = template.Must(template.New("diff-html-page").Funcs(template.FuncMap{
	"dict": func(pairs ...any) map[string]any {
		m := make(map[string]any, len(pairs)/2)
		for i := 0; i < len(pairs)-1; i += 2 {
			m[pairs[i].(string)] = pairs[i+1]
		}
		return m
	},
}).Parse(diffHTMLPageTemplate))

func (d *Diff) String() string {
	var buf bytes.Buffer
	if err := diffMDTmpl.Execute(&buf, d); err != nil {
		return fmt.Errorf("failed to execute diff template: %s", err).Error()
	}
	return buf.String()
}

// ToJSON saves the diff as a JSON file
func (d *Diff) ToJSON() error {
	dat, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}

	if len(d.conf.Output) > 0 {
		if err := os.MkdirAll(d.conf.Output, 0755); err != nil {
			return err
		}
		fname := filepath.Join(d.conf.Output, d.TitleToFilename()+".json")
		log.Infof("Creating JSON diff file: %s", fname)
		return os.WriteFile(fname, dat, 0644)
	}

	fmt.Println(string(dat))

	return nil
}

type diffHTMLPageData struct {
	Title      string
	OldInput   string
	NewInput   string
	OldVersion string
	OldBuild   string
	NewVersion string
	NewBuild   string

	HasKernelVersion bool
	OldKernelDarwin  string
	OldKernelXNU     string
	OldKernelDate    string
	NewKernelDarwin  string
	NewKernelXNU     string
	NewKernelDate    string

	Kexts     *htmlMachoDiff
	KDKs      template.HTML
	Machos    *htmlMachoDiff
	Ents      template.HTML
	Sandbox   template.HTML
	Firmwares *htmlMachoDiff
	IBoot     *htmlIBootDiff
	Launchd   template.HTML
	Features  *htmlPlistDiff
	Files     *htmlFileDiff

	OldWebkit string
	NewWebkit string
	Dylibs    *htmlMachoDiff
}

type htmlMachoDiff struct {
	New     []string
	Removed []string
	Updated []htmlUpdatedEntry
}

type htmlUpdatedEntry struct {
	Name string
	Path string
	Diff template.HTML
}

type htmlNamedList struct {
	Name  string
	Items []string
}

type htmlIBootDiff struct {
	Versions []string
	New      []htmlNamedList
	Removed  []htmlNamedList
}

type htmlPlistEntry struct {
	Name    string
	Path    string
	Content template.HTML
}

type htmlPlistDiff struct {
	New     []htmlPlistEntry
	Removed []string
	Updated []htmlPlistEntry
}

type htmlFileDiff struct {
	New     []htmlNamedList
	Removed []htmlNamedList
}

const diffHTMLPageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <title>{{ .Title }}</title>
  <style>
    :root {
      --radius: 18px;
      --background: oklch(0.985 0.004 247.858);
      --foreground: oklch(0.205 0.01 257.417);
      --card: oklch(0.999 0 0);
      --card-foreground: oklch(0.205 0.01 257.417);
      --muted: oklch(0.968 0.006 247.896);
      --muted-foreground: oklch(0.473 0.013 255.508);
      --primary: oklch(0.598 0.112 221.723);
      --primary-foreground: oklch(0.985 0 0);
      --accent: oklch(0.929 0.03 214.91);
      --accent-foreground: oklch(0.278 0.033 256.848);
      --border: oklch(0.923 0.01 252.096);
      --shadow-soft: 0 24px 60px -32px oklch(0.188 0.012 257.417 / 0.28);
      --shadow-panel: 0 18px 40px -28px oklch(0.188 0.012 257.417 / 0.22);
      --code-bg: oklch(0.25 0.014 253.1);
      --code-fg: oklch(0.96 0.004 247.858);
      --diff-add: oklch(0.30 0.10 145);
      --diff-add-bg: oklch(0.96 0.03 145);
      --diff-del: oklch(0.38 0.10 25);
      --diff-del-bg: oklch(0.96 0.03 25);
      --diff-mod: oklch(0.40 0.10 75);
      --diff-mod-bg: oklch(0.96 0.03 75);
      --hero-wash: radial-gradient(circle at top left, oklch(0.96 0.04 215 / 0.9), transparent 38%),
        radial-gradient(circle at top right, oklch(0.92 0.025 250 / 0.75), transparent 34%),
        linear-gradient(135deg, oklch(0.995 0.002 247.858), oklch(0.975 0.01 247.896));
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --background: oklch(0.14 0.012 257.417);
        --foreground: oklch(0.96 0.004 247.858);
        --card: oklch(0.19 0.014 255.508);
        --card-foreground: oklch(0.96 0.004 247.858);
        --muted: oklch(0.24 0.012 255.508);
        --muted-foreground: oklch(0.7 0.013 255.508);
        --primary: oklch(0.72 0.104 221.723);
        --primary-foreground: oklch(0.205 0.01 257.417);
        --accent: oklch(0.28 0.02 224.12);
        --accent-foreground: oklch(0.96 0.004 247.858);
        --border: oklch(0.30 0.012 255.508);
        --shadow-soft: 0 30px 80px -40px oklch(0.02 0 0 / 0.65);
        --shadow-panel: 0 22px 46px -32px oklch(0.02 0 0 / 0.56);
        --code-bg: oklch(0.15 0.01 255.508);
        --code-fg: oklch(0.92 0.004 247.858);
        --diff-add: oklch(0.72 0.16 145);
        --diff-add-bg: oklch(0.22 0.04 145);
        --diff-del: oklch(0.72 0.16 25);
        --diff-del-bg: oklch(0.22 0.04 25);
        --diff-mod: oklch(0.76 0.12 75);
        --diff-mod-bg: oklch(0.22 0.03 75);
        --hero-wash: radial-gradient(circle at top left, oklch(0.26 0.036 215 / 0.55), transparent 38%),
          radial-gradient(circle at top right, oklch(0.22 0.02 250 / 0.5), transparent 34%),
          linear-gradient(135deg, oklch(0.18 0.012 257.417), oklch(0.15 0.012 255.508));
      }
    }

    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--foreground);
      background:
        radial-gradient(circle at top, oklch(0.9 0.02 215 / 0.18), transparent 30%),
        linear-gradient(180deg, color-mix(in oklab, var(--background) 92%, white 8%), var(--background));
      font-family: "Avenir Next", "Aptos", "Segoe UI", sans-serif;
      line-height: 1.65;
    }

    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image: linear-gradient(to right, color-mix(in oklab, var(--border) 40%, transparent) 1px, transparent 1px),
        linear-gradient(to bottom, color-mix(in oklab, var(--border) 35%, transparent) 1px, transparent 1px);
      background-size: 32px 32px;
      mask-image: linear-gradient(180deg, rgba(0, 0, 0, 0.35), transparent 75%);
      opacity: 0.28;
    }

    a { color: color-mix(in oklab, var(--primary) 82%, var(--foreground) 18%); text-decoration: none; }
    a:hover { color: var(--primary); }
    code, pre, kbd { font-family: "IBM Plex Mono", "SFMono-Regular", "SF Mono", Consolas, monospace; }

    .report-shell { position: relative; max-width: 1500px; margin: 0 auto; padding: 28px 22px 72px; }

    .panel {
      background: color-mix(in oklab, var(--card) 94%, transparent 6%);
      color: var(--card-foreground);
      border: 1px solid color-mix(in oklab, var(--border) 90%, transparent 10%);
      border-radius: calc(var(--radius) + 2px);
      box-shadow: var(--shadow-panel);
      backdrop-filter: blur(16px);
    }

    .report-hero { position: relative; overflow: hidden; margin-bottom: 24px; padding: 28px; background: var(--hero-wash); }

    .report-hero::after {
      content: "";
      position: absolute;
      inset: auto -10% -35% auto;
      width: 320px; height: 320px;
      border-radius: 50%;
      background: radial-gradient(circle, color-mix(in oklab, var(--primary) 32%, transparent 68%) 0%, transparent 72%);
      opacity: 0.9;
      pointer-events: none;
    }

    .hero-topline {
      display: inline-flex; align-items: center; gap: 10px;
      margin-bottom: 16px; padding: 8px 12px;
      border-radius: 999px;
      background: color-mix(in oklab, var(--card) 80%, transparent 20%);
      border: 1px solid color-mix(in oklab, var(--border) 80%, transparent 20%);
      color: var(--muted-foreground);
      font-size: 0.78rem; letter-spacing: 0.14em; text-transform: uppercase;
    }

    .hero-grid {
      position: relative; z-index: 1;
      display: grid; grid-template-columns: minmax(0, 1.7fr) minmax(280px, 1fr);
      gap: 18px; align-items: start;
    }

    .hero-title {
      margin: 0;
      font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", serif;
      font-size: clamp(2.2rem, 4vw, 4rem);
      line-height: 1.02; letter-spacing: -0.04em;
      text-wrap: balance;
    }

    .hero-subtitle { max-width: 62ch; margin: 14px 0 4px; color: var(--muted-foreground); font-size: 1rem; }

    .hero-meta { display: grid; gap: 12px; }
    .meta-card {
      padding: 16px 18px; border-radius: calc(var(--radius) - 4px);
      background: color-mix(in oklab, var(--card) 82%, transparent 18%);
      border: 1px solid color-mix(in oklab, var(--border) 76%, transparent 24%);
      box-shadow: var(--shadow-soft);
    }
    .meta-label { display: block; margin-bottom: 6px; color: var(--muted-foreground); font-size: 0.78rem; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; }
    .meta-value { display: block; font-size: 1rem; font-weight: 700; word-break: break-word; }
    .meta-note { display: block; margin-top: 6px; color: var(--muted-foreground); font-size: 0.92rem; }

    .report-layout { display: grid; grid-template-columns: minmax(240px, 300px) minmax(0, 1fr); gap: 24px; align-items: start; }
    .report-layout.no-sidebar { grid-template-columns: minmax(0, 1fr); }

    .report-sidebar { position: sticky; top: 22px; padding: 18px; }
    .sidebar-title { margin: 0 0 14px; font-size: 0.8rem; letter-spacing: 0.14em; text-transform: uppercase; color: var(--muted-foreground); }

    .toc ul { list-style: none; margin: 0; padding: 0; }
    .toc ul ul { margin-top: 6px; margin-left: 10px; padding-left: 10px; border-left: 1px solid color-mix(in oklab, var(--border) 82%, transparent 18%); }
    .toc li { margin: 2px 0; }
    .toc a {
      display: block; padding: 8px 10px; border-radius: 12px;
      color: var(--muted-foreground); font-size: 0.92rem; line-height: 1.35;
      transition: background-color 120ms ease, color 120ms ease, transform 120ms ease;
    }
    .toc a:hover { background: color-mix(in oklab, var(--accent) 70%, transparent 30%); color: var(--foreground); transform: translateX(2px); }

    .report-main { min-width: 0; padding: 30px 32px; }

    .rc h2, .rc h3, .rc h4, .rc h5 { scroll-margin-top: 28px; }
    .rc h2 {
      margin: 2.5rem 0 1rem; padding-top: 1.4rem;
      border-top: 1px solid color-mix(in oklab, var(--border) 88%, transparent 12%);
      font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", serif;
      font-size: clamp(1.55rem, 2vw, 2rem); line-height: 1.15; letter-spacing: -0.03em;
      text-wrap: balance;
    }
    .rc h2:first-of-type { margin-top: 0; padding-top: 0; border-top: 0; }
    .rc h3, .rc h4, .rc h5 {
      margin: 1.6rem 0 0.7rem; font-size: 0.82rem; font-weight: 800;
      letter-spacing: 0.16em; text-transform: uppercase; color: var(--muted-foreground);
    }
    .rc p, .rc li, .rc blockquote, .rc summary { font-size: 0.98rem; }
    .rc p { max-width: 74ch; }
    .rc ul, .rc ol { padding-left: 1.35rem; }
    .rc li + li { margin-top: 0.28rem; }
    .rc li::marker { color: color-mix(in oklab, var(--primary) 75%, var(--foreground) 25%); }

    .rc table {
      width: 100%; display: block; overflow-x: auto;
      margin: 1.2rem 0 1.6rem; border-collapse: separate; border-spacing: 0;
      border: 1px solid color-mix(in oklab, var(--border) 88%, transparent 12%);
      border-radius: calc(var(--radius) - 6px);
      background: color-mix(in oklab, var(--card) 92%, transparent 8%);
    }
    .rc thead th {
      background: color-mix(in oklab, var(--muted) 84%, transparent 16%);
      color: var(--foreground); font-size: 0.82rem; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase;
    }
    .rc caption {
      caption-side: bottom;
      padding: 12px 14px 0;
      color: var(--muted-foreground);
      font-size: 0.9rem;
      text-align: left;
    }
    .rc th, .rc td { padding: 12px 14px; border-bottom: 1px solid color-mix(in oklab, var(--border) 82%, transparent 18%); text-align: left; white-space: nowrap; }
    .rc tr:last-child td { border-bottom: 0; }
    .rc tbody tr:nth-child(even) { background: color-mix(in oklab, var(--muted) 48%, transparent 52%); }

    .rc blockquote {
      margin: 1.1rem 0; padding: 0.9rem 1rem;
      border-left: 3px solid color-mix(in oklab, var(--primary) 68%, transparent 32%);
      border-radius: 0 14px 14px 0;
      background: color-mix(in oklab, var(--accent) 52%, transparent 48%);
      color: var(--foreground);
    }

    .rc code {
      padding: 0.18rem 0.44rem; border-radius: 0.55rem;
      background: color-mix(in oklab, var(--muted) 72%, transparent 28%);
      color: var(--foreground); font-size: 0.88em;
    }

    .rc pre {
      overflow-x: auto; margin: 1rem 0 1.4rem; padding: 16px 18px;
      border: 1px solid color-mix(in oklab, var(--border) 60%, transparent 40%);
      border-radius: calc(var(--radius) - 4px);
      background: linear-gradient(180deg, color-mix(in oklab, var(--code-bg) 88%, black 12%), var(--code-bg));
      color: var(--code-fg);
      box-shadow: inset 0 1px 0 color-mix(in oklab, white 8%, transparent 92%);
    }
    .rc pre code { padding: 0; background: transparent; color: inherit; border-radius: 0; font-size: 0.9rem; }

    .rc .diff-add { color: var(--diff-add); background: var(--diff-add-bg); display: inline-block; width: 100%; padding: 0 4px; margin: 0 -4px; border-radius: 3px; }
    .rc .diff-del { color: var(--diff-del); background: var(--diff-del-bg); display: inline-block; width: 100%; padding: 0 4px; margin: 0 -4px; border-radius: 3px; }
    .rc .diff-mod { color: var(--diff-mod); background: var(--diff-mod-bg); display: inline-block; width: 100%; padding: 0 4px; margin: 0 -4px; border-radius: 3px; }

    .rc details {
      margin: 1.1rem 0 1.5rem; padding: 0.45rem 1rem 1rem;
      border: 1px solid color-mix(in oklab, var(--border) 85%, transparent 15%);
      border-radius: calc(var(--radius) - 4px);
      background: color-mix(in oklab, var(--card) 90%, transparent 10%);
    }
    .rc details[open] { box-shadow: var(--shadow-soft); }
    .rc summary {
      display: flex; align-items: center; justify-content: space-between; gap: 16px;
      cursor: pointer; list-style: none; font-weight: 700; color: var(--foreground); padding: 0.6rem 0;
      transition: color 150ms ease;
    }
    .rc summary:hover { color: var(--primary); }
    .rc summary::-webkit-details-marker { display: none; }
    .rc summary::after {
      content: "+"; display: inline-flex; align-items: center; justify-content: center;
      width: 1.6rem; height: 1.6rem; border-radius: 999px;
      background: color-mix(in oklab, var(--accent) 72%, transparent 28%);
      color: var(--accent-foreground); font-size: 1rem; font-weight: 700; flex-shrink: 0;
      transition: transform 200ms ease, background-color 150ms ease;
    }
    .rc summary:hover::after { background: color-mix(in oklab, var(--primary) 30%, var(--accent) 70%); }
    .rc details[open] summary::after { content: "\2212"; transform: rotate(180deg); }

    .rc .diff-entry { margin: 1.5rem 0; padding-top: 1rem; border-top: 1px solid color-mix(in oklab, var(--border) 60%, transparent 40%); }
    .rc .diff-entry:first-child { border-top: 0; padding-top: 0; margin-top: 0.5rem; }
    .rc .diff-entry-path {
      display: block; margin: 0.3rem 0 0.6rem; padding: 0.5rem 0.8rem;
      border-left: 3px solid color-mix(in oklab, var(--primary) 68%, transparent 32%);
      border-radius: 0 10px 10px 0;
      background: color-mix(in oklab, var(--accent) 40%, transparent 60%);
      color: var(--muted-foreground); font-size: 0.85rem;
    }
    .rc .diff-entry-path code { background: transparent; padding: 0; font-size: 0.82rem; }

    .rc hr { margin: 2rem 0; border: 0; border-top: 1px solid color-mix(in oklab, var(--border) 88%, transparent 12%); }

    a:focus-visible, summary:focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; border-radius: 6px; }
    .toc a.active { background: color-mix(in oklab, var(--primary) 15%, transparent 85%); color: var(--foreground); font-weight: 600; }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; scroll-behavior: auto !important; }
    }

    @media (max-width: 1100px) {
      .hero-grid, .report-layout, .report-layout.no-sidebar { grid-template-columns: minmax(0, 1fr); }
      .report-sidebar { position: static; }
      .report-main { padding: 24px 22px; }
    }

    @media (max-width: 700px) {
      .report-shell { padding: 18px 14px 40px; }
      .report-hero { padding: 22px 18px; }
      .hero-title { font-size: 2rem; }
      .report-main { padding: 20px 16px; }
    }
  </style>
</head>
<body>
  <div class="report-shell">
    <header class="report-hero panel">
      <div class="hero-topline">
        <span>ipsw</span>
        <span>Diff Report</span>
      </div>
      <div class="hero-grid">
        <section>
          <h1 class="hero-title">{{ .Title }}</h1>
        </section>
        <section class="hero-meta">
          <div class="meta-card">
            <span class="meta-label">Old Input</span>
            <span class="meta-value">{{ .OldInput }}</span>
            {{- if .OldVersion }}<span class="meta-note">{{ .OldVersion }} &middot; {{ .OldBuild }}</span>{{ end }}
          </div>
          <div class="meta-card">
            <span class="meta-label">New Input</span>
            <span class="meta-value">{{ .NewInput }}</span>
            {{- if .NewVersion }}<span class="meta-note">{{ .NewVersion }} &middot; {{ .NewBuild }}</span>{{ end }}
          </div>
        </section>
      </div>
    </header>
    <div class="report-layout">
      <aside class="report-sidebar panel">
        <h2 class="sidebar-title">Contents</h2>
        <nav class="toc">
          <ul>
            <li><a href="#inputs">Inputs</a></li>
            <li><a href="#kernel">Kernel</a>
              {{- if .HasKernelVersion }}<ul><li><a href="#kernel-version">Version</a></li></ul>{{ end }}
            </li>
            {{- if .Kexts }}
            <li><a href="#kexts">Kexts</a>
              <ul>
                {{- if .Kexts.New }}<li><a href="#kexts-new">New ({{ len .Kexts.New }})</a></li>{{ end }}
                {{- if .Kexts.Removed }}<li><a href="#kexts-removed">Removed ({{ len .Kexts.Removed }})</a></li>{{ end }}
                {{- if .Kexts.Updated }}<li><a href="#kexts-updated">Updated ({{ len .Kexts.Updated }})</a></li>{{ end }}
              </ul>
            </li>
            {{- end }}
            {{- if .Machos }}
            <li><a href="#machos">MachOs</a>
              <ul>
                {{- if .Machos.New }}<li><a href="#machos-new">New ({{ len .Machos.New }})</a></li>{{ end }}
                {{- if .Machos.Removed }}<li><a href="#machos-removed">Removed ({{ len .Machos.Removed }})</a></li>{{ end }}
                {{- if .Machos.Updated }}<li><a href="#machos-updated">Updated ({{ len .Machos.Updated }})</a></li>{{ end }}
              </ul>
            </li>
            {{- end }}
            {{- if .Ents }}<li><a href="#entitlements">Entitlements</a></li>{{ end }}
            {{- if .Firmwares }}
            <li><a href="#firmwares">Firmwares</a>
              <ul>
                {{- if .Firmwares.New }}<li><a href="#fw-new">New ({{ len .Firmwares.New }})</a></li>{{ end }}
                {{- if .Firmwares.Removed }}<li><a href="#fw-removed">Removed ({{ len .Firmwares.Removed }})</a></li>{{ end }}
                {{- if .Firmwares.Updated }}<li><a href="#fw-updated">Updated ({{ len .Firmwares.Updated }})</a></li>{{ end }}
              </ul>
            </li>
            {{- end }}
            {{- if .IBoot }}
            <li><a href="#iboot">iBoot</a>
              <ul>
                {{- if .IBoot.New }}<li><a href="#iboot-new">New ({{ len .IBoot.New }})</a></li>{{ end }}
                {{- if .IBoot.Removed }}<li><a href="#iboot-removed">Removed ({{ len .IBoot.Removed }})</a></li>{{ end }}
              </ul>
            </li>
            {{- end }}
            {{- if .Launchd }}<li><a href="#launchd">launchd Config</a></li>{{ end }}
            {{- if .Sandbox }}<li><a href="#sandbox-profiles">Sandbox Profiles</a></li>{{ end }}
            <li><a href="#dsc">DSC</a>
              <ul>
                {{- if .OldWebkit }}<li><a href="#webkit">WebKit</a></li>{{ end }}
                {{- if .Dylibs }}
                <li><a href="#dylibs">Dylibs</a>
                  <ul>
                    {{- if .Dylibs.New }}<li><a href="#dylibs-new">New ({{ len .Dylibs.New }})</a></li>{{ end }}
                    {{- if .Dylibs.Removed }}<li><a href="#dylibs-removed">Removed ({{ len .Dylibs.Removed }})</a></li>{{ end }}
                    {{- if .Dylibs.Updated }}<li><a href="#dylibs-updated">Updated ({{ len .Dylibs.Updated }})</a></li>{{ end }}
                  </ul>
                </li>
                {{- end }}
              </ul>
            </li>
            {{- if .Files }}
            <li><a href="#files">Files</a>
              <ul>
                {{- if .Files.New }}<li><a href="#files-new">New ({{ len .Files.New }})</a></li>{{ end }}
                {{- if .Files.Removed }}<li><a href="#files-removed">Removed ({{ len .Files.Removed }})</a></li>{{ end }}
              </ul>
            </li>
            {{- end }}
            {{- if .Features }}
            <li><a href="#feature-flags">Feature Flags</a>
              <ul>
                {{- if .Features.New }}<li><a href="#features-new">New ({{ len .Features.New }})</a></li>{{ end }}
                {{- if .Features.Removed }}<li><a href="#features-removed">Removed ({{ len .Features.Removed }})</a></li>{{ end }}
                {{- if .Features.Updated }}<li><a href="#features-updated">Updated ({{ len .Features.Updated }})</a></li>{{ end }}
              </ul>
            </li>
            {{- end }}
          </ul>
        </nav>
      </aside>
      <main class="report-main panel">
        <article class="rc">

          <h2 id="inputs">Inputs</h2>
          <ul>
            <li><code>{{ .OldInput }}</code></li>
            <li><code>{{ .NewInput }}</code></li>
          </ul>

          <h2 id="kernel">Kernel</h2>
          {{- if .HasKernelVersion }}
          <h3 id="kernel-version">Version</h3>
          <table>
            <caption>Kernel version comparison across the old and new inputs.</caption>
            <thead><tr><th>iOS</th><th>Version</th><th>Build</th><th>Date</th></tr></thead>
            <tbody>
              <tr><td>{{ .OldVersion }} <em>({{ .OldBuild }})</em></td><td>{{ .OldKernelDarwin }}</td><td>{{ .OldKernelXNU }}</td><td>{{ .OldKernelDate }}</td></tr>
              <tr><td>{{ .NewVersion }} <em>({{ .NewBuild }})</em></td><td>{{ .NewKernelDarwin }}</td><td>{{ .NewKernelXNU }}</td><td>{{ .NewKernelDate }}</td></tr>
            </tbody>
          </table>
          {{- end }}

          {{- if .Kexts }}
          <h3 id="kexts">Kexts</h3>
          {{- template "machoDiffSection" dict "Prefix" "kexts" "Diff" .Kexts }}
          {{- end }}

          {{- if .KDKs }}
          <h2 id="kdks">KDKs</h2>
          {{ .KDKs }}
          {{- end }}

          {{- if .Machos }}
          <h2 id="machos">MachOs</h2>
          {{- template "machoDiffSection" dict "Prefix" "machos" "Diff" .Machos }}
          {{- end }}

          {{- if .Ents }}
          <h3 id="entitlements">Entitlements</h3>
          <details>
            <summary>View Entitlements</summary>
            {{ .Ents }}
          </details>
          {{- end }}

          {{- if .Firmwares }}
          <h2 id="firmwares">Firmwares</h2>
          {{- template "machoDiffSection" dict "Prefix" "fw" "Diff" .Firmwares }}
          {{- end }}

          {{- if .IBoot }}
          <h2 id="iboot">iBoot</h2>
          {{- if ge (len .IBoot.Versions) 2 }}
          <table>
            <caption>iBoot version comparison across the old and new inputs.</caption>
            <thead><tr><th>iOS</th><th>Version</th></tr></thead>
            <tbody>
              <tr><td>{{ .OldVersion }} <em>({{ .OldBuild }})</em></td><td>{{ index .IBoot.Versions 0 }}</td></tr>
              <tr><td>{{ .NewVersion }} <em>({{ .NewBuild }})</em></td><td>{{ index .IBoot.Versions 1 }}</td></tr>
            </tbody>
          </table>
          {{- end }}
          {{- if .IBoot.New }}
          <h3 id="iboot-new">New</h3>
          <details>
            <summary>View New ({{ len .IBoot.New }})</summary>
            {{- range .IBoot.New }}
            <div class="diff-entry">
              <h4>{{ .Name }}</h4>
              <ul>{{ range .Items }}<li><code>{{ . }}</code></li>{{ end }}</ul>
            </div>
            {{- end }}
          </details>
          {{- end }}
          {{- if .IBoot.Removed }}
          <h3 id="iboot-removed">Removed</h3>
          <details>
            <summary>View Removed ({{ len .IBoot.Removed }})</summary>
            {{- range .IBoot.Removed }}
            <div class="diff-entry">
              <h4>{{ .Name }}</h4>
              <ul>{{ range .Items }}<li><code>{{ . }}</code></li>{{ end }}</ul>
            </div>
            {{- end }}
          </details>
          {{- end }}
          {{- end }}

          {{- if .Launchd }}
          <h2 id="launchd">launchd Config</h2>
          {{ .Launchd }}
          {{- end }}

          {{- if .Sandbox }}
          <h2 id="sandbox-profiles">Sandbox Profiles</h2>
          {{ .Sandbox }}
          {{- end }}

          <h2 id="dsc">DSC</h2>
          {{- if .OldWebkit }}
          <h3 id="webkit">WebKit</h3>
          <table>
            <caption>WebKit version comparison across the old and new inputs.</caption>
            <thead><tr><th>iOS</th><th>Version</th></tr></thead>
            <tbody>
              <tr><td>{{ .OldVersion }} <em>({{ .OldBuild }})</em></td><td>{{ .OldWebkit }}</td></tr>
              <tr><td>{{ .NewVersion }} <em>({{ .NewBuild }})</em></td><td>{{ .NewWebkit }}</td></tr>
            </tbody>
          </table>
          {{- end }}

          {{- if .Dylibs }}
          <h3 id="dylibs">Dylibs</h3>
          {{- template "machoDiffSection" dict "Prefix" "dylibs" "Diff" .Dylibs }}
          {{- end }}

          {{- if .Files }}
          <h2 id="files">Files</h2>
          {{- if .Files.New }}
          <h3 id="files-new">New</h3>
          {{- range .Files.New }}
          <div class="diff-entry">
            <h4>{{ .Name }} ({{ len .Items }})</h4>
            <ul>{{ range .Items }}<li><code>{{ . }}</code></li>{{ end }}</ul>
          </div>
          {{- end }}
          {{- end }}
          {{- if .Files.Removed }}
          <h3 id="files-removed">Removed</h3>
          {{- range .Files.Removed }}
          <div class="diff-entry">
            <h4>{{ .Name }} ({{ len .Items }})</h4>
            <ul>{{ range .Items }}<li><code>{{ . }}</code></li>{{ end }}</ul>
          </div>
          {{- end }}
          {{- end }}
          {{- end }}

          {{- if .Features }}
          <h2 id="feature-flags">Feature Flags</h2>
          {{- if .Features.New }}
          <h3 id="features-new">New</h3>
          <details>
            <summary>View New ({{ len .Features.New }})</summary>
            {{- range .Features.New }}
            <div class="diff-entry">
              <h4>{{ .Name }}</h4>
              <div class="diff-entry-path"><code>{{ .Path }}</code></div>
              {{ .Content }}
            </div>
            {{- end }}
          </details>
          {{- end }}
          {{- if .Features.Removed }}
          <h3 id="features-removed">Removed</h3>
          <ul>{{ range .Features.Removed }}<li><code>{{ . }}</code></li>{{ end }}</ul>
          {{- end }}
          {{- if .Features.Updated }}
          <h3 id="features-updated">Updated</h3>
          <details>
            <summary>View Updated ({{ len .Features.Updated }})</summary>
            {{- range .Features.Updated }}
            <div class="diff-entry">
              <h4>{{ .Name }}</h4>
              <div class="diff-entry-path"><code>{{ .Path }}</code></div>
              {{ .Content }}
            </div>
            {{- end }}
          </details>
          {{- end }}
          {{- end }}

        </article>
      </main>
    </div>
  </div>
  <script>
  (function(){
    var links=document.querySelectorAll('.toc a[href^="#"]');
    if(!links.length)return;
    var ids=[];links.forEach(function(a){ids.push(a.getAttribute('href').slice(1));});
    var io=new IntersectionObserver(function(entries){
      entries.forEach(function(e){
        if(e.isIntersecting){
          links.forEach(function(a){a.classList.remove('active');});
          var match=document.querySelector('.toc a[href="#'+e.target.id+'"]');
          if(match)match.classList.add('active');
        }
      });
    },{rootMargin:'-20% 0px -60% 0px'});
    ids.forEach(function(id){var el=document.getElementById(id);if(el)io.observe(el);});
  })();
  </script>
</body>
</html>

{{ define "machoDiffSection" }}
{{- if .Diff.New }}
<h4 id="{{ .Prefix }}-new">New</h4>
<ul>{{ range .Diff.New }}<li><code>{{ . }}</code></li>{{ end }}</ul>
{{- end }}
{{- if .Diff.Removed }}
<h4 id="{{ .Prefix }}-removed">Removed</h4>
<ul>{{ range .Diff.Removed }}<li><code>{{ . }}</code></li>{{ end }}</ul>
{{- end }}
{{- if .Diff.Updated }}
<h4 id="{{ .Prefix }}-updated">Updated</h4>
<details>
  <summary>View Updated ({{ len .Diff.Updated }})</summary>
  {{- range .Diff.Updated }}
  <div class="diff-entry">
    <h5>{{ .Name }}</h5>
    <div class="diff-entry-path"><code>{{ .Path }}</code></div>
    <pre><code>{{ .Diff }}</code></pre>
  </div>
  {{- end }}
</details>
{{- end }}
{{ end }}
`

func renderCodeBlock(raw string) template.HTML {
	if raw == "" {
		return ""
	}

	var buf strings.Builder
	buf.WriteString("<pre><code>")
	buf.WriteString(html.EscapeString(raw))
	buf.WriteString("</code></pre>")
	return template.HTML(buf.String())
}

func stripDiffFence(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "```diff") {
		return raw
	}

	body := strings.TrimPrefix(trimmed, "```diff")
	body = strings.TrimPrefix(body, "\r\n")
	body = strings.TrimPrefix(body, "\n")

	if idx := strings.LastIndex(body, "\n```"); idx >= 0 {
		return body[:idx]
	}
	if before, ok := strings.CutSuffix(body, "```"); ok {
		return before
	}

	return raw
}

func renderMarkdownChunk(md string) string {
	if strings.TrimSpace(md) == "" {
		return ""
	}

	renderer := mdhtml.NewRenderer(mdhtml.RendererOptions{
		Flags: mdhtml.CommonFlags,
	})
	return string(markdown.ToHTML([]byte(md), nil, renderer))
}

func highlightDiff(raw string) template.HTML {
	var buf strings.Builder
	first := true
	for line := range strings.SplitSeq(raw, "\n") {
		if !first {
			buf.WriteByte('\n')
		}
		first = false
		escaped := html.EscapeString(line)
		switch {
		case strings.HasPrefix(line, "+"):
			buf.WriteString(`<span class="diff-add">`)
			buf.WriteString(escaped)
			buf.WriteString("</span>")
		case strings.HasPrefix(line, "-"):
			buf.WriteString(`<span class="diff-del">`)
			buf.WriteString(escaped)
			buf.WriteString("</span>")
		case strings.HasPrefix(line, "~"):
			buf.WriteString(`<span class="diff-mod">`)
			buf.WriteString(escaped)
			buf.WriteString("</span>")
		default:
			buf.WriteString(escaped)
		}
	}
	return template.HTML(buf.String())
}

func renderHighlightedDiffBlock(raw string) string {
	if raw == "" {
		return ""
	}

	var buf strings.Builder
	buf.WriteString("<pre><code>")
	buf.WriteString(string(highlightDiff(raw)))
	buf.WriteString("</code></pre>")
	return buf.String()
}

func renderMarkdownFragment(md string) template.HTML {
	if md == "" {
		return ""
	}

	var out strings.Builder
	var markdownBuf strings.Builder
	var diffBuf strings.Builder
	inDiffFence := false

	flushMarkdown := func() {
		if markdownBuf.Len() == 0 {
			return
		}
		out.WriteString(renderMarkdownChunk(markdownBuf.String()))
		markdownBuf.Reset()
	}

	flushDiff := func() {
		if diffBuf.Len() == 0 {
			return
		}
		out.WriteString(renderHighlightedDiffBlock(diffBuf.String()))
		diffBuf.Reset()
	}

	lines := strings.Split(md, "\n")
	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)

		if inDiffFence {
			if trimmed == "```" {
				flushDiff()
				inDiffFence = false
				continue
			}
			if diffBuf.Len() > 0 {
				diffBuf.WriteByte('\n')
			}
			diffBuf.WriteString(line)
			continue
		}

		if trimmed == "```diff" {
			flushMarkdown()
			inDiffFence = true
			continue
		}

		markdownBuf.WriteString(line)
		if idx < len(lines)-1 {
			markdownBuf.WriteByte('\n')
		}
	}

	if inDiffFence {
		markdownBuf.WriteString("```diff\n")
		markdownBuf.WriteString(diffBuf.String())
	}

	flushMarkdown()

	return template.HTML(out.String())
}

func convertMachoDiff(md *mcmd.MachoDiff) *htmlMachoDiff {
	if md == nil {
		return nil
	}
	h := &htmlMachoDiff{
		New:     md.New,
		Removed: md.Removed,
	}
	for _, k := range slices.Sorted(maps.Keys(md.Updated)) {
		h.Updated = append(h.Updated, htmlUpdatedEntry{
			Name: filepath.Base(k),
			Path: k,
			Diff: highlightDiff(stripDiffFence(md.Updated[k])),
		})
	}
	return h
}

func sortedNamedLists(m map[string][]string) []htmlNamedList {
	var out []htmlNamedList
	for _, k := range slices.Sorted(maps.Keys(m)) {
		out = append(out, htmlNamedList{
			Name:  k,
			Items: slices.Sorted(slices.Values(m[k])),
		})
	}
	return out
}

func convertIBootDiff(ib *IBootDiff) *htmlIBootDiff {
	if ib == nil {
		return nil
	}

	out := &htmlIBootDiff{
		Versions: append([]string(nil), ib.Versions...),
		New:      sortedNamedLists(ib.New),
		Removed:  sortedNamedLists(ib.Removed),
	}

	if len(out.Versions) == 0 && len(out.New) == 0 && len(out.Removed) == 0 {
		return nil
	}

	return out
}

func convertPlistDiff(pd *PlistDiff) *htmlPlistDiff {
	if pd == nil {
		return nil
	}

	out := &htmlPlistDiff{
		Removed: slices.Sorted(slices.Values(pd.Removed)),
	}

	for _, k := range slices.Sorted(maps.Keys(pd.New)) {
		out.New = append(out.New, htmlPlistEntry{
			Name:    filepath.Base(k),
			Path:    k,
			Content: renderCodeBlock(pd.New[k]),
		})
	}

	for _, k := range slices.Sorted(maps.Keys(pd.Updated)) {
		out.Updated = append(out.Updated, htmlPlistEntry{
			Name:    filepath.Base(k),
			Path:    k,
			Content: renderMarkdownFragment(pd.Updated[k]),
		})
	}

	if len(out.New) == 0 && len(out.Removed) == 0 && len(out.Updated) == 0 {
		return nil
	}

	return out
}

func convertFileDiff(fd *FileDiff) *htmlFileDiff {
	if fd == nil {
		return nil
	}

	order := []string{"IPSW", "filesystem", "SystemOS", "AppOS", "ExclaveOS"}
	out := &htmlFileDiff{}

	for _, name := range order {
		if items, ok := fd.New[name]; ok && len(items) > 0 {
			out.New = append(out.New, htmlNamedList{Name: name, Items: slices.Sorted(slices.Values(items))})
		}
	}

	for _, name := range order {
		if items, ok := fd.Removed[name]; ok && len(items) > 0 {
			out.Removed = append(out.Removed, htmlNamedList{Name: name, Items: slices.Sorted(slices.Values(items))})
		}
	}

	if len(out.New) == 0 && len(out.Removed) == 0 {
		return nil
	}

	return out
}

func (d *Diff) renderHTML() (string, error) {
	var htmlBuf bytes.Buffer

	data := diffHTMLPageData{
		Title:      d.Title,
		OldInput:   filepath.Base(d.Old.IPSWPath),
		NewInput:   filepath.Base(d.New.IPSWPath),
		OldVersion: d.Old.Version,
		OldBuild:   d.Old.Build,
		NewVersion: d.New.Version,
		NewBuild:   d.New.Build,
		OldWebkit:  d.Old.Webkit,
		NewWebkit:  d.New.Webkit,
		Kexts:      convertMachoDiff(d.Kexts),
		Machos:     convertMachoDiff(d.Machos),
		Dylibs:     convertMachoDiff(d.Dylibs),
		Firmwares:  convertMachoDiff(d.Firmwares),
		IBoot:      convertIBootDiff(d.IBoot),
		Features:   convertPlistDiff(d.Features),
		Files:      convertFileDiff(d.Files),
		Ents:       renderMarkdownFragment(d.Ents),
		Sandbox:    renderMarkdownFragment(d.Sandbox),
		KDKs:       renderMarkdownFragment(d.KDKs),
		Launchd:    renderMarkdownFragment(d.Launchd),
	}

	if d.Old.Kernel.Version != nil {
		data.HasKernelVersion = true
		data.OldKernelDarwin = d.Old.Kernel.Version.KernelVersion.Darwin
		data.OldKernelXNU = d.Old.Kernel.Version.KernelVersion.XNU
		data.OldKernelDate = d.Old.Kernel.Version.KernelVersion.Date.Format(
			"Mon, 02 Jan 2006 15:04:05 MST",
		)
	}
	if d.New.Kernel.Version != nil {
		data.NewKernelDarwin = d.New.Kernel.Version.KernelVersion.Darwin
		data.NewKernelXNU = d.New.Kernel.Version.KernelVersion.XNU
		data.NewKernelDate = d.New.Kernel.Version.KernelVersion.Date.Format(
			"Mon, 02 Jan 2006 15:04:05 MST",
		)
	}

	if err := diffHTMLTmpl.Execute(&htmlBuf, data); err != nil {
		return "", err
	}

	return htmlBuf.String(), nil
}

func (d *Diff) ToHTML() error {
	rendered, err := d.renderHTML()
	if err != nil {
		return err
	}

	if len(d.conf.Output) == 0 {
		fmt.Println(rendered)
		return nil
	}

	if err := os.MkdirAll(d.conf.Output, 0755); err != nil {
		return err
	}

	fname := filepath.Join(d.conf.Output, d.TitleToFilename()+".html")
	log.Infof("Creating HTML diff file: %s", fname)
	return os.WriteFile(fname, []byte(rendered), 0644)
}
