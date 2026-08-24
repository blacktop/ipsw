package download

import (
	"context"
	"log/slog"
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
	logger, ok := log.Log.(*log.Logger)
	return ok && logger.Level <= log.DebugLevel
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
	entry := log.WithFields(fields)
	message := "godl: " + record.Message
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
