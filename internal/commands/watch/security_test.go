package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blacktop/ipsw/internal/download"
)

func TestPollSecurityBaselineReportsNothing(t *testing.T) {
	t.Parallel()

	site := newFakeSecuritySite(
		testSecurityRow{id: "900003", name: "FakeOS 9.2", date: "2 Oct 2099"},
		testSecurityRow{id: "900002", name: "FakeOS 9.1", date: "1 Oct 2099"},
		testSecurityRow{id: "900001", name: "FakeOS 8", date: "1 Aug 2026"},
	)
	site.publish(t, "900003", "v1", testSecurityVuln{cve: "CVE-2099-0001", names: []string{"Fake Finder"}})

	poll := pollFakeSecurity(t, site, SecurityState{}, SecurityPollOptions{})

	if len(poll.Events) != 0 {
		t.Fatalf("baseline without --notify-initial produced events: %+v", poll.Events)
	}
	if !poll.Baselined || !poll.State.Initialized {
		t.Fatalf("expected an initialized baseline, got %+v", poll)
	}
	if _, ok := poll.State.Advisories["900003"]; !ok || len(poll.State.Advisories) != 1 {
		t.Fatalf("unexpected stored advisories: %+v", poll.State.Advisories)
	}
	if poll.NoJSON != 1 {
		t.Fatalf("expected one advisory without JSON, got %d", poll.NoJSON)
	}
	if got, want := site.requestedIDs(), []string{"900003", "900002"}; !slices.Equal(got, want) {
		t.Fatalf("requested %v, want %v (advisories before JSON era must not be requested)", got, want)
	}
}

func TestPollSecurityNotifyInitialMatchesCreditNamesOnly(t *testing.T) {
	t.Parallel()

	site := newFakeSecuritySite(testSecurityRow{id: "900003", name: "FakeOS 9.2", date: "2 Oct 2099"})
	site.publish(t, "900003", "v1",
		testSecurityVuln{
			cve:          "CVE-2099-0001",
			component:    "FakeKit",
			names:        []string{"Fake Finder of Example Labs"},
			organization: "Example Labs",
		},
		testSecurityVuln{cve: "CVE-2099-0002", names: []string{"Other Person"}, organization: "Fake Finder Org"},
		testSecurityVuln{cve: "CVE-2099-0003"},
	)

	poll := pollFakeSecurity(t, site, SecurityState{}, SecurityPollOptions{
		NotifyInitial: true,
		Credits:       []string{"FAKE FINDER"},
	})

	want := []SecurityEvent{{
		Kind:        SecurityNewAdvisory,
		Advisory:    "900003",
		Name:        "FakeOS 9.2",
		URL:         "https://support.apple.com/en-us/900003",
		ReleaseDate: "2099-10-02",
		CVE:         "CVE-2099-0001",
		Component:   "FakeKit",
		Credits:     []string{"Fake Finder of Example Labs"},
	}}
	if !reflect.DeepEqual(poll.Events, want) {
		t.Fatalf("unexpected events:\n got %+v\nwant %+v", poll.Events, want)
	}
	stored := poll.State.Advisories["900003"].Vulnerabilities
	if len(stored) != 3 {
		t.Fatalf("credit filter must not affect stored state, got %+v", stored)
	}
	if stored["CVE-2099-0003"].Credits != nil {
		t.Fatalf("vulnerability without acknowledgments stored credits: %+v", stored["CVE-2099-0003"])
	}
}

func TestPollSecurityReportsAddedCVE(t *testing.T) {
	t.Parallel()

	site := newFakeSecuritySite(testSecurityRow{id: "900003", name: "FakeOS 9.2", date: "2 Oct 2099"})
	site.publish(t, "900003", "v1", testSecurityVuln{cve: "CVE-2099-0001"})
	state := pollFakeSecurity(t, site, SecurityState{}, SecurityPollOptions{}).State

	site.publish(t, "900003", "v2",
		testSecurityVuln{cve: "CVE-2099-0001"},
		testSecurityVuln{cve: "CVE-2099-0009", component: "FakeKernel", names: []string{"Late Finder"}},
	)
	poll := pollFakeSecurity(t, site, state, SecurityPollOptions{})

	if len(poll.Events) != 1 {
		t.Fatalf("expected one event, got %+v", poll.Events)
	}
	event := poll.Events[0]
	if event.Kind != SecurityCVEAdded || event.CVE != "CVE-2099-0009" ||
		event.Component != "FakeKernel" || !slices.Equal(event.Credits, []string{"Late Finder"}) {
		t.Fatalf("unexpected event: %+v", event)
	}
	if poll.State.Advisories["900003"].ETag != "v2" {
		t.Fatalf("stored ETag was not updated: %+v", poll.State.Advisories["900003"])
	}
}

func TestPollSecurityReportsChangedCreditsProductsAndImpact(t *testing.T) {
	t.Parallel()

	site := newFakeSecuritySite(testSecurityRow{id: "900003", name: "FakeOS 9.2", date: "2 Oct 2099"})
	site.publish(t, "900003", "v1", testSecurityVuln{
		cve:    "CVE-2099-0001",
		impact: "An app may crash",
		names:  []string{"Fake Finder"},
		fixed:  []string{"FAKE-os-9"},
	})
	state := pollFakeSecurity(t, site, SecurityState{}, SecurityPollOptions{}).State

	site.publish(t, "900003", "v2", testSecurityVuln{
		cve:    "CVE-2099-0001",
		impact: "An app may gain kernel privileges",
		names:  []string{"Fake Finder of Example Labs"},
		fixed:  []string{"FAKE-padOS-9", "FAKE-os-9"},
	})
	poll := pollFakeSecurity(t, site, state, SecurityPollOptions{})

	type change struct {
		kind           SecurityEventKind
		added, removed []string
		old, new       string
	}
	var got []change
	for _, event := range poll.Events {
		got = append(got, change{event.Kind, event.Added, event.Removed, event.Old, event.New})
	}
	want := []change{
		{kind: SecurityCreditsChanged, added: []string{"Fake Finder of Example Labs"}, removed: []string{"Fake Finder"}},
		{kind: SecurityProductsChanged, added: []string{"FAKE-padOS-9"}},
		{kind: SecurityImpactChanged, old: "An app may crash", new: "An app may gain kernel privileges"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected events:\n got %+v\nwant %+v", got, want)
	}
}

func TestPollSecurityCreditFilterMatchesPreviousCredits(t *testing.T) {
	t.Parallel()

	site := newFakeSecuritySite(testSecurityRow{id: "900003", name: "FakeOS 9.2", date: "2 Oct 2099"})
	site.publish(t, "900003", "v1",
		testSecurityVuln{cve: "CVE-2099-0001", names: []string{"Fake Finder"}},
		testSecurityVuln{cve: "CVE-2099-0002", names: []string{"Fake Finder"}},
	)
	state := pollFakeSecurity(t, site, SecurityState{}, SecurityPollOptions{}).State

	site.publish(t, "900003", "v2", testSecurityVuln{cve: "CVE-2099-0001", names: []string{"Another Person"}})
	poll := pollFakeSecurity(t, site, state, SecurityPollOptions{Credits: []string{"fake finder"}})

	var got []string
	for _, event := range poll.Events {
		got = append(got, string(event.Kind)+" "+event.CVE)
	}
	want := []string{"credits_changed CVE-2099-0001", "cve_removed CVE-2099-0002"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPollSecurityUsesConditionalRequests(t *testing.T) {
	t.Parallel()

	site := newFakeSecuritySite(testSecurityRow{id: "900003", name: "FakeOS 9.2", date: "2 Oct 2099"})
	site.publish(t, "900003", `"etag-1"`, testSecurityVuln{cve: "CVE-2099-0001"})
	state := pollFakeSecurity(t, site, SecurityState{}, SecurityPollOptions{}).State

	poll := pollFakeSecurity(t, site, state, SecurityPollOptions{NotifyInitial: true})

	if len(poll.Events) != 0 || poll.NotModified != 1 {
		t.Fatalf("expected one 304 and no events, got %+v", poll)
	}
	if got := site.requests[len(site.requests)-1].ifNoneMatch; got != `"etag-1"` {
		t.Fatalf("second request sent If-None-Match %q", got)
	}
	if _, ok := poll.State.Advisories["900003"].Vulnerabilities["CVE-2099-0001"]; !ok {
		t.Fatalf("304 dropped stored content: %+v", poll.State.Advisories["900003"])
	}
}

func TestPollSecurityThrottleStopsPassAndNamesAdvisory(t *testing.T) {
	t.Parallel()

	site := newFakeSecuritySite(
		testSecurityRow{id: "900005", name: "FakeOS 9.4", date: "4 Oct 2099"},
		testSecurityRow{id: "900004", name: "FakeOS 9.3", date: "3 Oct 2099"},
		testSecurityRow{id: "900003", name: "FakeOS 9.2", date: "2 Oct 2099"},
	)
	site.publish(t, "900005", "v1", testSecurityVuln{cve: "CVE-2099-0005"})
	site.publish(t, "900004", "v1", testSecurityVuln{cve: "CVE-2099-0004"})
	site.publish(t, "900003", "v1", testSecurityVuln{cve: "CVE-2099-0003"})
	site.advisories["900004"].status = http.StatusTooManyRequests

	poll := pollFakeSecurity(t, site, SecurityState{}, SecurityPollOptions{})

	if got, want := site.requestedIDs(), []string{"900005", "900004", "900004", "900004"}; !slices.Equal(got, want) {
		t.Fatalf("requested %v, want %v", got, want)
	}
	err := poll.UnfetchedError()
	if len(poll.Unfetched) != 2 ||
		!strings.Contains(err.Error(), "security advisory 900004: HTTP 429 after 3 attempts") ||
		!strings.Contains(err.Error(), "security advisory 900003: not requested after HTTP 429") {
		t.Fatalf("error does not name the throttled advisories: %v", err)
	}
	if poll.State.Initialized {
		t.Fatal("a partial baseline must stay uninitialized so unfetched advisories baseline silently later")
	}
	if _, ok := poll.State.Advisories["900005"]; !ok {
		t.Fatalf("advisory fetched before throttling was not stored: %+v", poll.State.Advisories)
	}
}

func TestSecurityStateRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "watch", "security.json")
	want := SecurityState{
		Version:     securityStateVersion,
		Initialized: true,
		Advisories: map[string]SecurityAdvisory{"900003": {
			Name:            "FakeOS 9.2",
			ETag:            `"etag-1"`,
			Vulnerabilities: map[string]SecurityVulnerability{"CVE-2099-0001": {Credits: []string{"Fake Finder"}}},
		}},
	}
	if err := SaveSecurityState(path, want); err != nil {
		t.Fatalf("SaveSecurityState: %v", err)
	}
	got, err := LoadSecurityState(path)
	if err != nil {
		t.Fatalf("LoadSecurityState: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
	missing, err := LoadSecurityState(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || missing.Initialized {
		t.Fatalf("missing state should load as uninitialized, got %+v, %v", missing, err)
	}
}

type testSecurityRow struct {
	id, name, date string
}

type testSecurityVuln struct {
	cve, component, impact string
	names                  []string
	organization           string
	fixed                  []string
}

type fakeSecurityAdvisory struct {
	etag   string
	body   []byte
	status int
}

type fakeSecurityRequest struct {
	id          string
	ifNoneMatch string
}

type fakeSecuritySite struct {
	index      string
	advisories map[string]*fakeSecurityAdvisory
	requests   []fakeSecurityRequest
}

func newFakeSecuritySite(rows ...testSecurityRow) *fakeSecuritySite {
	var index strings.Builder
	index.WriteString("<table><tr><th>Name</th><th>Available for</th><th>Release date</th></tr>")
	for _, row := range rows {
		fmt.Fprintf(&index,
			`<tr><td><p><a href="https://support.apple.com/en-us/%s">%s</a></p></td><td><p>Fake Device</p></td><td><p>%s</p></td></tr>`,
			row.id, row.name, row.date,
		)
	}
	index.WriteString("</table>")
	return &fakeSecuritySite{index: index.String(), advisories: make(map[string]*fakeSecurityAdvisory)}
}

func (s *fakeSecuritySite) publish(t *testing.T, id, etag string, vulns ...testSecurityVuln) {
	t.Helper()
	type acknowledgment struct {
		Names        []string `json:"names"`
		Organization string   `json:"organization,omitempty"`
	}
	items := make([]map[string]any, 0, len(vulns))
	for _, vuln := range vulns {
		item := map[string]any{
			"cve":   vuln.cve,
			"title": vuln.component,
			"notes": []map[string]string{
				{"category": "summary", "title": "Impact", "text": vuln.impact},
				{"category": "details", "title": "Description", "text": "Fake description of " + vuln.cve},
				{"category": "general", "title": "Available for", "text": "Fake Device"},
			},
			"product_status": map[string]any{"fixed": vuln.fixed},
		}
		if vuln.names != nil {
			item["acknowledgments"] = []acknowledgment{{Names: vuln.names, Organization: vuln.organization}}
		}
		items = append(items, item)
	}
	body, err := json.Marshal(map[string]any{
		"document":        map[string]any{"title": "About the security content of FakeOS"},
		"vulnerabilities": items,
	})
	if err != nil {
		t.Fatalf("failed to encode fake advisory: %v", err)
	}
	s.advisories[id] = &fakeSecurityAdvisory{etag: etag, body: body}
}

func (s *fakeSecuritySite) requestedIDs() []string {
	ids := make([]string, 0, len(s.requests))
	for _, request := range s.requests {
		ids = append(ids, request.id)
	}
	return ids
}

func (s *fakeSecuritySite) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.String() == download.SecurityIndexURL {
		return fakeSecurityResponse(request, http.StatusOK, s.index, nil), nil
	}
	id := strings.TrimSuffix(path.Base(request.URL.Path), ".json")
	ifNoneMatch := request.Header.Get("If-None-Match")
	s.requests = append(s.requests, fakeSecurityRequest{id: id, ifNoneMatch: ifNoneMatch})

	advisory, ok := s.advisories[id]
	switch {
	case !ok:
		return fakeSecurityResponse(request, http.StatusNotFound, "<html>not found</html>", nil), nil
	case advisory.status != 0:
		return fakeSecurityResponse(request, advisory.status, "<html>throttled</html>", nil), nil
	case ifNoneMatch == advisory.etag:
		return fakeSecurityResponse(request, http.StatusNotModified, "", nil), nil
	default:
		header := http.Header{"Etag": []string{advisory.etag}}
		return fakeSecurityResponse(request, http.StatusOK, string(advisory.body), header), nil
	}
}

func fakeSecurityResponse(request *http.Request, status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func pollFakeSecurity(t *testing.T, site *fakeSecuritySite, state SecurityState, opts SecurityPollOptions) SecurityPoll {
	t.Helper()
	client := &download.SecurityClient{
		HTTP:    &http.Client{Transport: site},
		Backoff: []time.Duration{time.Millisecond, time.Millisecond},
	}
	poll, err := PollSecurity(context.Background(), client, state, opts)
	if err != nil {
		t.Fatalf("PollSecurity returned error: %v", err)
	}
	return poll
}
