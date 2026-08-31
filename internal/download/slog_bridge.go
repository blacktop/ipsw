package download

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/apex/log"
	godl "github.com/blacktop/go-download"
)

// engineLog bridges go-download's structured internals (election, effective
// tuple, protocol, retries, 429 shedding, connected addresses, placement,
// resume, integrity) into apex/log so --verbose surfaces the engine's
// measurements instead of silently discarding them.
var engineLog = slog.New(slogBridge{})

// slogBridge is a slog.Handler forwarding records to apex/log. The engine
// documents Logger as "debug-level internals", so records normally land at
// apex debug — but warnings and errors keep their severity and are never
// dropped by the debug gate.
type slogBridge struct {
	attrs []slog.Attr
}

func (b slogBridge) Enabled(_ context.Context, level slog.Level) bool {
	if level >= slog.LevelWarn {
		return true
	}
	return apexDebugEnabled()
}

func (b slogBridge) Handle(_ context.Context, record slog.Record) error {
	fields := make(log.Fields, record.NumAttrs()+len(b.attrs))
	add := func(attr slog.Attr) bool {
		fields[attr.Key] = redactAttrValue(attr.Value)
		return true
	}
	for _, attr := range b.attrs {
		add(attr)
	}
	record.Attrs(add)
	message := "godl: " + record.Message
	// Bars own the terminal: interleaving through the live container keeps
	// the in-place redraw intact. A failed writer is retried against older
	// live containers; apex takes the line only when none remains.
	if writeThroughProgressSink(formatProgressLogLine(record.Level, message, fields) + "\n") {
		return nil
	}
	entry := log.WithFields(fields)
	switch {
	case record.Level >= slog.LevelError:
		entry.Error(message)
	case record.Level >= slog.LevelWarn:
		entry.Warn(message)
	default:
		entry.Debug(message)
	}
	return nil
}

func (b slogBridge) WithAttrs(attrs []slog.Attr) slog.Handler {
	return slogBridge{attrs: append(slices.Clip(b.attrs), attrs...)}
}

func (b slogBridge) WithGroup(string) slog.Handler { return b } // the engine emits no groups

// apexDebugEnabled reports whether the process-wide apex logger surfaces
// debug records (--verbose).
func apexDebugEnabled() bool {
	logger, ok := log.Log.(*log.Logger)
	return ok && logger.Level <= log.DebugLevel
}

// formatProgressLogLine renders one engine record as a single plain line for
// the progress container: apex-style bullet, message, then fields in sorted
// key order so the output is deterministic.
func formatProgressLogLine(level slog.Level, message string, fields log.Fields) string {
	symbol := "•"
	switch {
	case level >= slog.LevelError:
		symbol = "⨯"
	case level >= slog.LevelWarn:
		symbol = "⚠"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "   %s %s", symbol, message)
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		fmt.Fprintf(&sb, " %s=%v", key, fields[key])
	}
	return sb.String()
}

// redactAttrValue strips signed query credentials from URL-shaped values.
// The engine already redacts URLs at its emit sites; this is defense in
// depth against a future engine regression, not a leak being papered over.
func redactAttrValue(value slog.Value) any {
	resolved := value.Resolve().Any()
	if s, ok := resolved.(string); ok &&
		(strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")) {
		return godl.RedactURL(s)
	}
	return resolved
}
