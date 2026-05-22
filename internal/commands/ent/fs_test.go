package ent

import (
	"bytes"
	"strings"
	"testing"
)

func TestFilesystemQueryMatchesHasWithout(t *testing.T) {
	record := filesystemEntitlementRecord{
		Path: "/System/Library/ExtensionKit/Extensions/WebKit.GPU.xpc/WebKit.GPU",
		Entitlements: Entitlements{
			"com.apple.developer.hardened-process": true,
			"com.apple.private.foo":                "bar",
		},
	}

	query := FilesystemQuery{
		Has:          []string{"com.apple.developer.hardened-process"},
		Without:      []string{"com.apple.security.hardened-process.checked-allocations.soft-mode"},
		FilePattern:  "WebKit.GPU",
		ValuePattern: "bar",
	}

	if !query.matches(record) {
		t.Fatal("expected record to match hardened-process query")
	}

	query.Without = []string{"com.apple.private.foo"}
	if query.matches(record) {
		t.Fatal("expected record to be excluded by --without")
	}

	query = FilesystemQuery{Has: []string{"com.apple.developer.hardened"}}
	if query.matches(record) {
		t.Fatal("expected --has to require exact entitlement keys")
	}

	query = FilesystemQuery{KeyPattern: "developer.hardened"}
	if !query.matches(record) {
		t.Fatal("expected --key search to keep substring matching")
	}
}

func TestNormalizeEntitlementPatternsSplitsCommaValues(t *testing.T) {
	got := normalizeEntitlementPatterns([]string{
		"com.apple.a, com.apple.b",
		"com.apple.c",
		"",
	})
	want := []string{"com.apple.a", "com.apple.b", "com.apple.c"}
	if len(got) != len(want) {
		t.Fatalf("got %d patterns, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pattern %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestPrintFilesystemJSONLHonorsFileOnly(t *testing.T) {
	records := []filesystemEntitlementRecord{{
		Path: "/usr/libexec/testd",
		Entitlements: Entitlements{
			"com.apple.private.foo": true,
		},
	}}
	var buf bytes.Buffer
	if err := printFilesystemJSONLTo(&buf, records, true); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(buf.String())
	want := `{"path":"/usr/libexec/testd"}`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
