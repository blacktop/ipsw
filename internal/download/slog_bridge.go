package download

import (
	"context"
	"log/slog"
	"slices"
	"strings"

	"github.com/apex/log"
	godl "github.com/blacktop/go-download"
)

// engineLogger bridges go-download's structured internals (election, effective
// tuple, protocol, retries, 429 shedding, connected addresses, placement,
// resume, integrity) into apex/log so --verbose surfaces the engine's
// measurements instead of silently discarding them.
func engineLogger() *slog.Logger {
	return slog.New(slogBridge{})
}

// slogBridge is a slog.Handler that forwards records to apex/log at debug
// level, redacting URL-shaped attribute values (signed query credentials).
type slogBridge struct {
	attrs []slog.Attr
}

func (b slogBridge) Enabled(context.Context, slog.Level) bool {
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
	log.WithFields(fields).Debug("godl: " + record.Message)
	return nil
}

func (b slogBridge) WithAttrs(attrs []slog.Attr) slog.Handler {
	return slogBridge{attrs: append(slices.Clip(b.attrs), attrs...)}
}

func (b slogBridge) WithGroup(string) slog.Handler { return b } // the engine emits no groups

// redactAttrValue strips signed query credentials from URL-shaped values.
func redactAttrValue(value slog.Value) any {
	resolved := value.Resolve().Any()
	if s, ok := resolved.(string); ok &&
		(strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")) {
		return godl.RedactURL(s)
	}
	return resolved
}
