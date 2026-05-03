package diff

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
)

func newHTMLTestDiff(title string) *Diff {
	return New(&Config{
		Title:   title,
		IpswOld: "old.ipsw",
		IpswNew: "new.ipsw",
	})
}

func mustRenderHTML(t *testing.T, d *Diff) string {
	t.Helper()

	rendered, err := d.renderHTML()
	if err != nil {
		t.Fatalf("renderHTML returned error: %v", err)
	}

	return rendered
}

func TestRenderHTMLUsesStaticShellAndStripsMarkdownTOC(t *testing.T) {
	rendered := mustRenderHTML(t, newHTMLTestDiff("Example Diff"))

	if !strings.Contains(rendered, `class="report-shell"`) {
		t.Fatalf("rendered HTML missing report shell")
	}
	if strings.Contains(rendered, `cdn.jsdelivr.net/npm/bulma`) {
		t.Fatalf("rendered HTML should not include Bulma CDN")
	}
	if !strings.Contains(rendered, `<aside class="report-sidebar panel">`) {
		t.Fatalf("rendered HTML missing contents sidebar")
	}
}

func TestRenderHTMLTitleNotCorrupted(t *testing.T) {
	d := newHTMLTestDiff("23D8133__iPhone17,1 .vs 23D771330a__iPhone17,1")
	d.Old.IPSWPath = "/path/to/23D8133__iPhone17,1"
	d.New.IPSWPath = "/path/to/23D771330a__iPhone17,1"
	rendered := mustRenderHTML(t, d)

	if strings.Contains(rendered, "<strong>") {
		t.Fatalf("title corrupted: __ interpreted as markdown bold")
	}
	if !strings.Contains(rendered, "23D8133__iPhone17,1") {
		t.Fatalf("title missing literal underscores")
	}
}

func TestRenderHTMLTOCAnchorsWork(t *testing.T) {
	rendered := mustRenderHTML(t, newHTMLTestDiff("Test Diff"))

	if !strings.Contains(rendered, `href="#inputs"`) {
		t.Fatalf("TOC missing #inputs link")
	}
	if !strings.Contains(rendered, `id="inputs"`) {
		t.Fatalf("content missing id=inputs anchor")
	}
	if !strings.Contains(rendered, `href="#kernel"`) {
		t.Fatalf("TOC missing #kernel link")
	}
	if !strings.Contains(rendered, `id="kernel"`) {
		t.Fatalf("content missing id=kernel anchor")
	}
}

func TestRenderHTMLDiffHighlighting(t *testing.T) {
	d := newHTMLTestDiff("Test Diff")
	d.Dylibs = &mcmd.MachoDiff{
		Updated: map[string]string{
			"/System/Library/Frameworks/WebCore.framework/WebCore": "```diff\n+added line\n-removed line\n~modified line\n unchanged line\n```",
		},
	}
	rendered := mustRenderHTML(t, d)

	if !strings.Contains(rendered, `class="diff-add"`) {
		t.Fatalf("missing diff-add highlighting")
	}
	if !strings.Contains(rendered, `class="diff-del"`) {
		t.Fatalf("missing diff-del highlighting")
	}
	if !strings.Contains(rendered, `class="diff-mod"`) {
		t.Fatalf("missing diff-mod highlighting")
	}
	if strings.Contains(rendered, "```diff") || strings.Contains(rendered, "\n```</code></pre>") {
		t.Fatalf("diff fence markers leaked into rendered HTML")
	}
}

func TestRenderHTMLDetailsRendered(t *testing.T) {
	d := newHTMLTestDiff("Test Diff")
	d.Dylibs = &mcmd.MachoDiff{
		Updated: map[string]string{
			"/System/Library/Frameworks/Test.framework/Test": "some diff content",
		},
	}
	rendered := mustRenderHTML(t, d)

	if !strings.Contains(rendered, "<details>") {
		t.Fatalf("missing details element")
	}
	if !strings.Contains(rendered, "View Updated") {
		t.Fatalf("missing details summary text")
	}
	if !strings.Contains(rendered, "some diff content") {
		t.Fatalf("details content not rendered")
	}
	if strings.Contains(rendered, "```diff") {
		t.Fatalf("raw markdown code fence in HTML output")
	}
}

func TestRenderHTMLIncludesIBootFilesAndFeatureFlags(t *testing.T) {
	d := newHTMLTestDiff("Test Diff")
	d.Old.Version = "18.3.1"
	d.Old.Build = "23D8133"
	d.New.Version = "18.3.2"
	d.New.Build = "23E123"
	d.IBoot = &IBootDiff{
		Versions: []string{"iBoot-1000.0", "iBoot-1001.0"},
		New: map[string][]string{
			"iBoot": {"new-symbol"},
		},
	}
	d.Files = &FileDiff{
		New: map[string][]string{
			"filesystem": {"System/Library/NewFile"},
		},
		Removed: map[string][]string{
			"IPSW": {"Firmware/old.im4p"},
		},
	}
	d.Features = &PlistDiff{
		New: map[string]string{
			"/System/Library/FeatureFlags/Test.plist": "<plist><dict><key>Enabled</key><true/></dict></plist>",
		},
		Removed: []string{"/System/Library/FeatureFlags/Old.plist"},
		Updated: map[string]string{
			"/System/Library/FeatureFlags/Changed.plist": "```diff\n- old\n+ new\n```",
		},
	}
	rendered := mustRenderHTML(t, d)

	for _, needle := range []string{
		`id="iboot"`,
		`id="files"`,
		`id="feature-flags"`,
		`new-symbol`,
		`System/Library/NewFile`,
		`Changed.plist`,
	} {
		if !strings.Contains(rendered, needle) {
			t.Fatalf("rendered HTML missing %q", needle)
		}
	}
}

func TestRenderHTMLIncludesSandboxProfiles(t *testing.T) {
	d := newHTMLTestDiff("Test Diff")
	d.Sandbox = "### Collection\n\n#### Changed (1)\n\n##### locationd\n\n```diff\n-(deny default)\n+(allow default)\n```\n"

	rendered := mustRenderHTML(t, d)

	for _, needle := range []string{
		`href="#sandbox-profiles"`,
		`id="sandbox-profiles"`,
		`locationd`,
		`class="diff-add"`,
		`class="diff-del"`,
	} {
		if !strings.Contains(rendered, needle) {
			t.Fatalf("rendered HTML missing %q", needle)
		}
	}
}

func TestStringIncludesSandboxProfiles(t *testing.T) {
	d := newHTMLTestDiff("Test Diff")
	d.Sandbox = "### Collection\n\n#### New (1)\n\n##### locationd\n\n```scheme\n(version 1)\n```\n"

	rendered := d.String()

	for _, needle := range []string{
		"## Sandbox Profiles",
		"### Collection",
		"##### locationd",
	} {
		if !strings.Contains(rendered, needle) {
			t.Fatalf("rendered Markdown missing %q", needle)
		}
	}
}

func TestJSONIncludesSandboxProfiles(t *testing.T) {
	d := newHTMLTestDiff("Test Diff")
	d.Sandbox = "### Collection\n\n#### Changed (1)\n"

	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if !strings.Contains(string(data), `"sandbox"`) {
		t.Fatalf("JSON missing sandbox field: %s", data)
	}
}

func TestRenderSandboxProfileDiffMarkdown(t *testing.T) {
	oldDocs := sandboxProfileDocuments{
		sandboxDiffSourceCollection: {
			"locationd": "(version 1)\n(deny default)\n",
			"removed":   "(version 1)\n",
		},
	}
	newDocs := sandboxProfileDocuments{
		sandboxDiffSourceCollection: {
			"locationd": "(version 1)\n(allow default)\n",
			"added":     "(version 1)\n(deny default)\n",
		},
	}

	rendered, err := renderSandboxProfileDiffMarkdown(oldDocs, newDocs)
	if err != nil {
		t.Fatalf("renderSandboxProfileDiffMarkdown returned error: %v", err)
	}

	for _, needle := range []string{
		"### Collection",
		"#### New (1)",
		"##### added",
		"#### Removed (1)",
		"##### removed",
		"#### Changed (1)",
		"##### locationd",
		"+(allow default)",
		"-(deny default)",
	} {
		if !strings.Contains(rendered, needle) {
			t.Fatalf("rendered sandbox diff missing %q:\n%s", needle, rendered)
		}
	}
}

func TestTitleToFilenameSanitizesDiffReportName(t *testing.T) {
	d := New(&Config{
		Title: "23D8133__iPhone17,1 .vs 23D771330a__iPhone17,1",
	})

	if got := d.TitleToFilename(); got != "23D8133__iPhone17,1_vs_23D771330a__iPhone17,1" {
		t.Fatalf("TitleToFilename() = %q, want %q", got, "23D8133__iPhone17,1_vs_23D771330a__iPhone17,1")
	}
}

func TestGeneratePreviewHTML(t *testing.T) {
	if os.Getenv("GENERATE_PREVIEW") == "" {
		t.Skip("set GENERATE_PREVIEW=1 to generate preview HTML")
	}

	d := newHTMLTestDiff("23D8133__iPhone17,1 .vs 23D771330a__iPhone17,1")
	d.Old.IPSWPath = "/path/to/23D8133__iPhone17,1"
	d.New.IPSWPath = "/path/to/23D771330a__iPhone17,1"
	d.Old.Version = "18.3.1"
	d.Old.Build = "23D8133"
	d.Old.Webkit = "623.2.7.10.4"
	d.New.Version = "18.3.1"
	d.New.Build = "23D771330a"
	d.New.Webkit = "623.2.7.110.1"

	d.Dylibs = &mcmd.MachoDiff{
		Updated: map[string]string{
			"/System/Library/PrivateFrameworks/ProductKit.framework/ProductKit": `-129.400.11.2.4
-  __TEXT.__text: 0x64154
+129.400.11.2.2
+  __TEXT.__text: 0x63f94
   __TEXT.__auth_stubs: 0x1e80
-  __TEXT.__const: 0x5fcc
+  __TEXT.__const: 0x5fac
-  UUID: 16F203DB-1540-37D3-A425-AD4DB581E414
+  UUID: FF372DCB-64D0-369B-9F1B-38D3E4CC5B21
   Functions: 2178

Functions:
~ sub_2657d4504 : 6744 -> 6520
~ sub_2657d5f5c -> sub_2657d5e7c : 204 -> 172
CStrings:
- "Mac17,6"
- "Mac17,7"
- "iPad16,10"
- "iPad16,11"`,
			"/System/Library/PrivateFrameworks/WebCore.framework/WebCore": `-623.2.7.10.4
-  __TEXT.__text: 0x325ebe4
+623.2.7.110.1
+  __TEXT.__text: 0x325ef34
   __TEXT.__auth_stubs: 0xd910

Symbols:
+ __ZNK3WTF10RefCountedIN7WebCore20SWServerRegistrationEE5derefEv
- __ZN7WebCore16SWServerJobQueue27cancelJobsFromServiceWorkerEN3WTF23ObjectIdentifierGenericINS_27ServiceWorkerIdentifierTypeE
- __ZNK3WTF27RefCountedAndCanMakeWeakPtrIN7WebCore20SWServerRegistrationEE5derefEv`,
		},
	}

	rendered := mustRenderHTML(t, d)
	outPath := "/tmp/ipsw-diff-preview.html"
	if err := os.WriteFile(outPath, []byte(rendered), 0644); err != nil {
		t.Fatalf("failed to write preview: %v", err)
	}
	t.Logf("Preview written to %s", outPath)
}
