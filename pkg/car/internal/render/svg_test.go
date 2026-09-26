package render

import (
	"fmt"
	"strings"
	"testing"
)

func TestRenderSVGResources(t *testing.T) {
	good := `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><defs><path id="p" d="M0 0h2v2z"/><linearGradient id="g"><stop stop-color="red"/></linearGradient></defs><use xlink:href="#p" fill="url('#g')"/></svg>`
	if err := validateRenderSVG([]byte(good)); err != nil {
		t.Fatal(err)
	}
	if err := validateRenderSVG([]byte(`<svg><path id="url-label"/><path id="url-label"/></svg>`)); err != nil {
		t.Fatal(err)
	}
	if err := validateRenderSVG(append([]byte{0xef, 0xbb, 0xbf}, []byte(good)...)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`<svg><image href="https://example.invalid/p.png"/></svg>`,
		`<svg><use href="file:///tmp/fake.svg#p"/></svg>`,
		`<svg><path fill="url(https://example.invalid/paint)"/></svg>`,
		`<svg><path style="fill:u\72l(file:///tmp/paint)"/></svg>`,
		`<svg><style>@import 'https://example.invalid/style';</style></svg>`,
		`<svg><path style="fill:/**/red"/></svg>`,
		`<svg><script>alert(1)</script></svg>`,
		`<svg onload="alert(1)"/>`,
		`<svg xml:base="https://example.invalid/"/>`,
		`<!DOCTYPE svg SYSTEM "file:///tmp/fake"><svg/>`,
		`<?xml-stylesheet href="file:///tmp/fake"?><svg/>`,
		`<svg><use href="#missing"/></svg>`,
		`<svg><use id="cycle" href="#cycle"/></svg>`,
		`<svg><g id="a"><use href="#b"/></g><g id="b"><use href="#a"/></g></svg>`,
		`<svg><path id="duplicate"/><use id="duplicate" href="#duplicate"/></svg>`,
		`<svg xmlns="https://example.invalid/namespace"/>`,
		`<svg/><svg/>`, `<svg>`, `text<svg/>`, `<path/>`, ``,
		`<svg>` + strings.Repeat(`<g>`, 64) + strings.Repeat(`</g>`, 64) + `</svg>`,
	} {
		if err := validateRenderSVG([]byte(bad)); err == nil {
			t.Errorf("accepted unsafe or invalid SVG: %.100s", bad)
		}
	}
}

func TestRenderSVGOrdinaryURLLetters(t *testing.T) {
	svg := `<svg><text fill="burlywood" font-family="Curlz MT" class="curl">label</text></svg>`
	if err := validateRenderSVG([]byte(svg)); err != nil {
		t.Fatalf("ordinary attribute values treated as resource references: %v", err)
	}
}

func TestRenderSVGExpansionBound(t *testing.T) {
	var svg strings.Builder
	svg.WriteString(`<svg><defs><path id="n0" d="M0 0h1v1z"/>`)
	for i := 1; i < 17; i++ {
		fmt.Fprintf(&svg, `<g id="n%d"><use href="#n%d"/><use href="#n%d"/></g>`, i, i-1, i-1)
	}
	svg.WriteString(`</defs><use href="#n16"/></svg>`)
	if err := validateRenderSVG([]byte(svg.String())); err == nil || !strings.Contains(err.Error(), "expansion") {
		t.Fatalf("unbounded expansion accepted: %v", err)
	}
}

func TestRenderSVGReferenceBounds(t *testing.T) {
	if refs, err := renderSVGReferences("style", "font-family:İ;fill:URL(#猫)"); err != nil || len(refs) != 1 || refs[0] != "猫" {
		t.Fatalf("Unicode changed reference offsets: %v %v", refs, err)
	}
	// Ambiguous IDs are rejected before building edges to every matching node.
	if err := validateRenderSVG([]byte(`<svg><path id="same"/><path id="same"/><use href="#same"/></svg>`)); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous reference accepted: %v", err)
	}
	refs := strings.Repeat("url(#p) ", maxRenderSVGReferences)
	if _, err := renderSVGReferences("style", refs+"url(#p)"); err == nil {
		t.Fatal("unbounded attribute references accepted")
	}
	for _, count := range []int{maxRenderSVGReferences, maxRenderSVGReferences / 2} {
		// Check both one large attribute and the aggregate across attributes.
		refAttr := strings.Repeat("url(#p) ", count)
		svg := `<svg><path id="p"/><path fill="` + refAttr + `" stroke="` + refAttr + `"/></svg>`
		if err := validateRenderSVG([]byte(svg)); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("unbounded reference graph accepted: %v", err)
		}
	}
}

func FuzzRenderSVG(f *testing.F) {
	f.Add([]byte(`<svg width="1" height="1"><path d="M0 0h1v1z"/></svg>`))
	f.Add([]byte(`<svg><use id="a" href="#a"/></svg>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_ = validateRenderSVG(data)
	})
}

func TestRenderSVGDeclaredEncoding(t *testing.T) {
	prefix := "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>"
	for _, body := range []string{
		`<svg xmlns="http://www.w3.org/2000/svg"><!--caf` + "\xe9" + `--></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><use href="https://example.invalid/a"/></svg>`,
	} {
		err := validateRenderSVG([]byte(prefix + body))
		if (err != nil) != strings.Contains(body, "https:") {
			t.Fatalf("encoded SVG validation: %v", err)
		}
	}
}
