package download

import (
	"fmt"
	"strings"
	"testing"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
)

func captureApexLog(t *testing.T, level log.Level) *memory.Handler {
	t.Helper()
	previous := log.Log
	handler := memory.New()
	log.Log = &log.Logger{Handler: handler, Level: level}
	t.Cleanup(func() { log.Log = previous })
	return handler
}

func TestEngineLoggerBridgesMeasurementsAtDebug(t *testing.T) {
	handler := captureApexLog(t, log.DebugLevel)

	logger := engineLog.With("url", "https://cdn.invalid/file.ipsw?accessKey=synthetic-secret")
	logger.Debug("election", "parts", 8, "protocol", "http/1.1")

	if len(handler.Entries) != 1 {
		t.Fatalf("bridged entries = %d, want 1", len(handler.Entries))
	}
	entry := handler.Entries[0]
	if entry.Message != "godl: election" {
		t.Fatalf("message = %q, want godl: election", entry.Message)
	}
	if entry.Level != log.DebugLevel {
		t.Fatalf("level = %v, want debug", entry.Level)
	}
	if got := entry.Fields["parts"]; fmt.Sprint(got) != "8" {
		t.Fatalf("parts field = %v, want 8", got)
	}
	url, _ := entry.Fields["url"].(string)
	if strings.Contains(url, "synthetic-secret") {
		t.Fatalf("bridged url leaks signed query values: %s", url)
	}
	if !strings.Contains(url, "cdn.invalid") {
		t.Fatalf("bridged url lost its host: %s", url)
	}
}

func TestEngineLoggerSilentBelowDebug(t *testing.T) {
	handler := captureApexLog(t, log.InfoLevel)

	engineLog.Debug("election", "parts", 8)
	engineLog.Info("resume", "bytes", 42)

	if len(handler.Entries) != 0 {
		t.Fatalf("bridged entries at info level = %d, want 0", len(handler.Entries))
	}
}

// TestEngineLoggerKeepsWarningSeverity pins that engine warnings (e.g. the
// stale-staging-link warning) reach users without --verbose, at warn level.
func TestEngineLoggerKeepsWarningSeverity(t *testing.T) {
	handler := captureApexLog(t, log.InfoLevel)

	engineLog.Warn("stale staging link left behind; remove it manually", "path", "/tmp/x.part")

	if len(handler.Entries) != 1 {
		t.Fatalf("bridged warn entries = %d, want 1 even without --verbose", len(handler.Entries))
	}
	if entry := handler.Entries[0]; entry.Level != log.WarnLevel {
		t.Fatalf("level = %v, want warn", entry.Level)
	}
}
