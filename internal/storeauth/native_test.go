package storeauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNativeSignWait(t *testing.T) {
	if got, err := nativeSignWait(context.Background()); err != nil || got != 20*time.Second {
		t.Fatalf("unbounded wait = %s, %v", got, err)
	}
	long, cancelLong := context.WithTimeout(context.Background(), time.Minute)
	defer cancelLong()
	if got, err := nativeSignWait(long); err != nil || got != 20*time.Second {
		t.Fatalf("long wait = %s, %v", got, err)
	}
	short, cancelShort := context.WithTimeout(context.Background(), time.Second)
	defer cancelShort()
	if got, err := nativeSignWait(short); err != nil || got <= 0 || got > time.Second {
		t.Fatalf("short wait = %s, %v", got, err)
	}
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if _, err := nativeSignWait(expired); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired wait error = %v", err)
	}
}

func TestNativeCallsRejectCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NativeHeaders(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("NativeHeaders canceled error = %v", err)
	}
	if _, err := Sign(ctx, []byte("synthetic request")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sign canceled error = %v", err)
	}
}

func syntheticNativeHeaders() map[string]string {
	return map[string]string{
		"X-Apple-I-MD":          "synthetic-md",
		"X-Apple-I-MD-M":        "synthetic-machine",
		"X-Apple-I-MD-RINFO":    "17106176",
		"X-Apple-I-MD-LU":       "",
		"X-Apple-I-Client-Time": "2001-01-01T00:00:00Z",
		"X-Apple-I-TimeZone":    "UTC",
		"X-Apple-Locale":        "en_US",
		"X-Mme-Device-Id":       "00000000-0000-0000-0000-000000000001",
		"X-Apple-I-SRL-NO":      "synthetic-serial",
		"X-MMe-Client-Info":     "synthetic-client",
	}
}

func TestNativeHeadersDecode(t *testing.T) {
	encoded, err := json.Marshal(syntheticNativeHeaders())
	if err != nil {
		t.Fatal(err)
	}
	headers, err := decodeNativeHeaders(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 10 || headers.Get("X-Apple-I-MD") != "synthetic-md" || headers.Get("X-Mme-Device-Id") != "00000000-0000-0000-0000-000000000001" {
		t.Fatal("decoded headers do not match the synthetic input")
	}

	for _, test := range []struct {
		name   string
		change func(map[string]string)
	}{
		{name: "missing", change: func(headers map[string]string) { delete(headers, "X-Apple-I-MD") }},
		{name: "empty", change: func(headers map[string]string) { headers["X-Apple-I-MD"] = "" }},
		{name: "extra", change: func(headers map[string]string) { headers["Authorization"] = "synthetic-secret" }},
		{name: "newline", change: func(headers map[string]string) { headers["X-Apple-I-MD"] = "synthetic-secret\r\nInjected: true" }},
		{name: "control", change: func(headers map[string]string) { headers["X-Apple-I-MD"] = "synthetic-secret\x00" }},
		{name: "size", change: func(headers map[string]string) { headers["X-Apple-I-MD"] = strings.Repeat("x", maxNativeHeaderBytes+1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := syntheticNativeHeaders()
			test.change(values)
			encoded, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeNativeHeaders(encoded); err == nil || err.Error() != "native anisette headers are invalid" {
				t.Fatalf("invalid headers error = %v", err)
			}
		})
	}
}

func TestNativeFailureRedaction(t *testing.T) {
	if got := nativeFailure("signing", "AMSErrorDomain", 1).Error(); got != "native App Store signing failed (domain=AMSErrorDomain code=1)" {
		t.Fatalf("safe NSError diagnostic = %q", got)
	}
	for _, domain := range []string{"", "synthetic-secret\n", strings.Repeat("x", 128)} {
		if got := nativeFailure("signing", domain, 1).Error(); got != "native App Store signing failed" {
			t.Fatalf("redacted NSError diagnostic = %q", got)
		}
	}
}
