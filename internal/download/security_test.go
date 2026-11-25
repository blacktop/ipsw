package download

import (
	"strings"
	"testing"
	"time"
)

const securityIndexSample = `<table class="gb-table"><tbody>
<tr><th><p>Name&nbsp;and&nbsp;information&nbsp;link</p></th><th><p>Available for</p></th><th><p>Release&nbsp;date</p></th></tr>
<tr><td><p>FakeOS 9.1</p><div class="note"><p>This update has no published CVE entries.</p></div></td><td><p>Fake Device</p></td><td><p>18 Nov 2099</p></td></tr>
<tr><td><p><a href="https://support.apple.com/en-us/900002" class="gb-anchor">FakeOS&nbsp;9 and FakePadOS 9</a></p></td><td><p>Fake Device</p></td><td><p>9 Nov 2099</p></td></tr>
<tr><td><p><a href="https://support.apple.com/en-us/900001">FakeOS 8.9</a></p></td><td><p>Fake Device</p></td><td><p>03 Aug 2026</p></td></tr>
</tbody></table>`

func TestParseSecurityIndex(t *testing.T) {
	t.Parallel()

	entries, err := ParseSecurityIndex(strings.NewReader(securityIndexSample))
	if err != nil {
		t.Fatalf("ParseSecurityIndex returned error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 rows, got %d: %+v", len(entries), entries)
	}

	if got := entries[0]; got.ID != "" || got.Name != "FakeOS 9.1" || got.ExpectsJSON() {
		t.Fatalf("unexpected row without CVEs: %+v", got)
	}
	linked := entries[1]
	if linked.ID != "900002" ||
		linked.Name != "FakeOS 9 and FakePadOS 9" ||
		linked.URL != "https://support.apple.com/en-us/900002" ||
		!linked.ReleaseDate.Equal(time.Date(2099, time.November, 9, 0, 0, 0, 0, time.UTC)) ||
		!linked.ExpectsJSON() {
		t.Fatalf("unexpected linked row: %+v", linked)
	}
	if entries[2].ID != "900001" || entries[2].ExpectsJSON() {
		t.Fatalf("advisory released before Apple published JSON should not expect JSON: %+v", entries[2])
	}
}

func TestParseSecurityIndexRejectsUnknownDate(t *testing.T) {
	t.Parallel()

	html := `<table><tr><td><a href="/en-us/900001">FakeOS 1</a></td><td>x</td><td>November 9, 2099</td></tr></table>`
	_, err := ParseSecurityIndex(strings.NewReader(html))
	if err == nil || !strings.Contains(err.Error(), "FakeOS 1") {
		t.Fatalf("expected an error naming the row, got %v", err)
	}
}

func TestParseSecurityIndexRejectsPageWithoutRows(t *testing.T) {
	t.Parallel()

	if _, err := ParseSecurityIndex(strings.NewReader("<html><p>maintenance</p></html>")); err == nil {
		t.Fatal("expected an error for a page without release rows")
	}
}
