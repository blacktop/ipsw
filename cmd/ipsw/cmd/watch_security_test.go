package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/internal/commands/watch"
)

func testSecurityEvents() []watch.SecurityEvent {
	first := watch.SecurityEvent{
		Advisory:    "900003",
		Name:        "FakeOS 9.2",
		URL:         "https://support.apple.com/en-us/900003",
		ReleaseDate: "2099-10-02",
		Component:   "FakeKit",
	}
	added := first
	added.Kind, added.CVE, added.Credits = watch.SecurityCVEAdded, "CVE-2099-0009", []string{"Fake Finder", "Other Person"}
	credits := first
	credits.Kind, credits.CVE = watch.SecurityCreditsChanged, "CVE-2099-0001"
	credits.Added, credits.Removed = []string{"Fake Finder of Example Labs"}, []string{"Fake Finder"}
	impact := first
	impact.Kind, impact.CVE, impact.New = watch.SecurityImpactChanged, "CVE-2099-0002", "An app may gain kernel privileges"
	second := watch.SecurityEvent{
		Kind:        watch.SecurityNewAdvisory,
		Advisory:    "900004",
		Name:        "FakeOS 9.3",
		URL:         "https://support.apple.com/en-us/900004",
		ReleaseDate: "2099-10-03",
		CVE:         "CVE-2099-0010",
		Component:   "FakeKernel",
	}
	return []watch.SecurityEvent{added, credits, impact, second}
}

func TestSecurityNotificationGroupsEventsByAdvisory(t *testing.T) {
	t.Parallel()

	groups := groupSecurityEvents(testSecurityEvents())
	if len(groups) != 2 || len(groups[0]) != 3 || len(groups[1]) != 1 {
		t.Fatalf("unexpected grouping: %+v", groups)
	}

	const want = `FakeOS 9.2 (2099-10-02)
https://support.apple.com/en-us/900003
  added       CVE-2099-0009    FakeKit (Fake Finder; Other Person)
  credits     CVE-2099-0001    FakeKit  +Fake Finder of Example Labs  -Fake Finder
  impact      CVE-2099-0002    FakeKit: An app may gain kernel privileges`
	if got := securityNotification(groups[0]); got != want {
		t.Fatalf("unexpected notification:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestEmitSecurityEventsWritesJSONLines(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	config := securityWatchConfig{json: true, output: &output}
	if err := emitSecurityEvents(context.Background(), testSecurityEvents(), config); err != nil {
		t.Fatalf("emitSecurityEvents: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected one line per event, got %d:\n%s", len(lines), output.String())
	}
	var event watch.SecurityEvent
	if err := json.Unmarshal([]byte(lines[1]), &event); err != nil {
		t.Fatalf("line is not JSON: %v\n%s", err, lines[1])
	}
	if event.Kind != watch.SecurityCreditsChanged || event.CVE != "CVE-2099-0001" || event.Removed[0] != "Fake Finder" {
		t.Fatalf("unexpected decoded event: %+v", event)
	}
}
