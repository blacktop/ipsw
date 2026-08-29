package download

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	"github.com/blacktop/ipsw/internal/download"
)

func TestAppledbNoUpdateFlagWiring(t *testing.T) {
	f := downloadAppledbCmd.Flags().Lookup("no-update")
	if f == nil {
		t.Fatal("appledb command is missing the no-update flag")
	}
	if f.DefValue != "false" {
		t.Fatalf("no-update default = %s, want false (update behavior preserved)", f.DefValue)
	}
}

func appleDBSource(t *testing.T, linksJSON string) download.OsFileSource {
	t.Helper()
	var source download.OsFileSource
	if err := json.Unmarshal([]byte(`{"type":"ipsw","deviceMap":["iPhone12,1"],"links":`+linksJSON+`}`), &source); err != nil {
		t.Fatalf("unmarshal source: %v", err)
	}
	return source
}

func appleDBRecord(t *testing.T, linksJSON string) download.AppleDBRecord {
	t.Helper()
	return download.AppleDBRecord{OsFileSource: appleDBSource(t, linksJSON)}
}

func appleDBReleasedDate(t *testing.T, value string) download.ReleasedDate {
	t.Helper()
	var released download.ReleasedDate
	if err := json.Unmarshal([]byte(`"`+value+`"`), &released); err != nil {
		t.Fatalf("unmarshal release date: %v", err)
	}
	return released
}

func TestNewAppleDBJSONEnvelopeUsesExplicitReleaseAndArtifactSchema(t *testing.T) {
	var source download.OsFileSource
	if err := json.Unmarshal([]byte(`{
		"type":"ota",
		"prerequisiteBuild":[],
		"deviceMap":["iPhone15,4"],
		"links":[{"url":"https://example.com/full.zip","active":true}],
		"hashes":{"sha2-256":"sha256-value","sha1":"sha1-value"},
		"size":123456
	}`), &source); err != nil {
		t.Fatalf("unmarshal source: %v", err)
	}

	records := []download.AppleDBRecord{{
		OS:           "iOS",
		Version:      "26.0 beta",
		Build:        "23A501",
		Released:     appleDBReleasedDate(t, "2026-08-20"),
		Channel:      "beta",
		OsFileSource: source,
	}}
	got, err := json.Marshal(newAppleDBJSONEnvelope(records))
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	const want = `{"schema_version":1,"releases":[{"os":"iOS","version":"26.0 beta","build":"23A501","release_date":"2026-08-20","channel":"beta","artifacts":[{"source_type":"ota","delivery":"full","prerequisite_builds":[],"devices":["iPhone15,4"],"links":[{"url":"https://example.com/full.zip","active":true}],"sha256":"sha256-value","sha1":"sha1-value","size":123456}]}]}`
	if string(got) != want {
		t.Fatalf("envelope JSON mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestAppleDBDeliveryClassifiesFullDeltaAndRSR(t *testing.T) {
	tests := []struct {
		name   string
		record download.AppleDBRecord
		want   string
	}{
		{name: "full", record: download.AppleDBRecord{OsFileSource: download.OsFileSource{Type: "ota"}}, want: "full"},
		{
			name: "delta",
			record: download.AppleDBRecord{OsFileSource: download.OsFileSource{
				Type:              "ota",
				PrerequisiteBuild: download.PrerequisiteBuilds{Builds: []string{"23A500"}},
			}},
			want: "delta",
		},
		{
			name: "rsr",
			record: download.AppleDBRecord{OsFileSource: download.OsFileSource{
				Type:              "rsr",
				PrerequisiteBuild: download.PrerequisiteBuilds{Builds: []string{"23A500"}},
			}},
			want: "rsr",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := appleDBDelivery(tt.record); got != tt.want {
				t.Fatalf("delivery = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestForEachAppleDBResultSkipsFailedResultAndSummarizes(t *testing.T) {
	results := []download.AppleDBRecord{
		appleDBRecord(t, `[{"url":"https://example.com/a/one.ipsw","active":true}]`),
		appleDBRecord(t, `[{"url":"https://developer.apple.com/services-account/download?path=/beta/two.ipsw","active":true}]`),
		appleDBRecord(t, `[{"url":"https://example.com/c/three.ipsw","active":true}]`),
	}
	var seen []string
	err := forEachAppleDBResult(context.Background(), results, func(idx int, _ download.AppleDBRecord, url string) error {
		seen = append(seen, url)
		if idx == 1 {
			return errors.New("boom")
		}
		return nil
	})
	if len(seen) != 3 {
		t.Fatalf("processed %d results, want 3 (batch must continue past a failure): %v", len(seen), seen)
	}
	if err == nil {
		t.Fatal("expected a summary error after a failed result")
	}
	want := "1 of 3 downloads failed: two.ipsw"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %q, want it to contain %q", err, want)
	}
}

func TestForEachAppleDBResultRedactsFailedURLCredentials(t *testing.T) {
	const secret = "synthetic-secret-Zx9q7Kv2Ln"
	const rawURL = "https://user:" + secret + "@cdn.example.invalid/path/firmware.ipsw?token=" + secret + "#" + secret

	previousLogger := log.Log
	handler := memory.New()
	log.Log = &log.Logger{Handler: handler, Level: log.InfoLevel}
	t.Cleanup(func() { log.Log = previousLogger })

	results := []download.AppleDBRecord{
		appleDBRecord(t, `[{"url":"`+rawURL+`","active":true}]`),
	}
	err := forEachAppleDBResult(context.Background(), results, func(int, download.AppleDBRecord, string) error {
		return errors.New("synthetic download failure")
	})
	if err == nil {
		t.Fatal("expected a summary error after the failed result")
	}
	if got := err.Error(); got != "1 of 1 downloads failed: firmware.ipsw" {
		t.Fatalf("err = %q, want credential-free path label", got)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("summary leaked URL credentials: %s", err)
	}
	if len(handler.Entries) != 1 {
		t.Fatalf("captured log entries = %d, want 1", len(handler.Entries))
	}
	message := handler.Entries[0].Message
	if strings.Contains(message, secret) || strings.Contains(message, "user:") {
		t.Fatalf("error log leaked URL credentials: %s", message)
	}
	if !strings.Contains(message, "https://cdn.example.invalid/path/firmware.ipsw?REDACTED") {
		t.Fatalf("error log = %q, want redacted URL", message)
	}
}

func TestForEachAppleDBResultReturnsNilWhenAllSucceed(t *testing.T) {
	results := []download.AppleDBRecord{
		appleDBRecord(t, `[{"url":"https://example.com/one.ipsw","active":true}]`),
		appleDBRecord(t, `[{"url":"https://example.com/two.ipsw","active":true}]`),
	}
	calls := 0
	err := forEachAppleDBResult(context.Background(), results, func(int, download.AppleDBRecord, string) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestForEachAppleDBResultStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := []download.AppleDBRecord{
		appleDBRecord(t, `[{"url":"https://example.com/one.ipsw","active":true}]`),
		appleDBRecord(t, `[{"url":"https://example.com/two.ipsw","active":true}]`),
	}
	calls := 0
	err := forEachAppleDBResult(ctx, results, func(int, download.AppleDBRecord, string) error {
		calls++
		cancel()
		return ctx.Err()
	})
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (batch must stop once interrupted)", calls)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestForEachAppleDBResultSkipsSourceWithoutActiveLink(t *testing.T) {
	results := []download.AppleDBRecord{
		appleDBRecord(t, `[{"url":"https://example.com/dead.ipsw","active":false}]`),
		appleDBRecord(t, `[{"url":"https://example.com/live.ipsw","active":true}]`),
	}
	var seen []string
	err := forEachAppleDBResult(context.Background(), results, func(_ int, _ download.AppleDBRecord, url string) error {
		seen = append(seen, url)
		return nil
	})
	if len(seen) != 1 || seen[0] != "https://example.com/live.ipsw" {
		t.Fatalf("processed %v, want only the live link", seen)
	}
	if err == nil || !strings.Contains(err.Error(), "1 of 2 downloads failed: iPhone12,1 (no active link)") {
		t.Fatalf("err = %v, want the inactive source reported", err)
	}
}

func TestActiveAppleDBLinkPrefersActiveLink(t *testing.T) {
	source := appleDBSource(t, `[
		{"url":"https://example.com/dead.ipsw","active":false},
		{"url":"https://example.com/live.ipsw","active":true}
	]`)
	if got := activeAppleDBLink(source); got != "https://example.com/live.ipsw" {
		t.Fatalf("activeAppleDBLink = %q, want the active link", got)
	}
	if got := activeAppleDBLink(download.OsFileSource{}); got != "" {
		t.Fatalf("activeAppleDBLink(empty) = %q, want empty", got)
	}
}
