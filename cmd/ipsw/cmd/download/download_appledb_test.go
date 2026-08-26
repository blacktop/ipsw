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

func TestForEachAppleDBResultSkipsFailedResultAndSummarizes(t *testing.T) {
	results := []download.OsFileSource{
		appleDBSource(t, `[{"url":"https://example.com/a/one.ipsw","active":true}]`),
		appleDBSource(t, `[{"url":"https://developer.apple.com/services-account/download?path=/beta/two.ipsw","active":true}]`),
		appleDBSource(t, `[{"url":"https://example.com/c/three.ipsw","active":true}]`),
	}
	var seen []string
	err := forEachAppleDBResult(context.Background(), results, func(idx int, _ download.OsFileSource, url string) error {
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

	results := []download.OsFileSource{
		appleDBSource(t, `[{"url":"`+rawURL+`","active":true}]`),
	}
	err := forEachAppleDBResult(context.Background(), results, func(int, download.OsFileSource, string) error {
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
	results := []download.OsFileSource{
		appleDBSource(t, `[{"url":"https://example.com/one.ipsw","active":true}]`),
		appleDBSource(t, `[{"url":"https://example.com/two.ipsw","active":true}]`),
	}
	calls := 0
	err := forEachAppleDBResult(context.Background(), results, func(int, download.OsFileSource, string) error {
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
	results := []download.OsFileSource{
		appleDBSource(t, `[{"url":"https://example.com/one.ipsw","active":true}]`),
		appleDBSource(t, `[{"url":"https://example.com/two.ipsw","active":true}]`),
	}
	calls := 0
	err := forEachAppleDBResult(ctx, results, func(int, download.OsFileSource, string) error {
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
	results := []download.OsFileSource{
		appleDBSource(t, `[{"url":"https://example.com/dead.ipsw","active":false}]`),
		appleDBSource(t, `[{"url":"https://example.com/live.ipsw","active":true}]`),
	}
	var seen []string
	err := forEachAppleDBResult(context.Background(), results, func(_ int, _ download.OsFileSource, url string) error {
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
