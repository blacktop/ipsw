package crashlog

import (
	"bytes"
	"compress/flate"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/color"
)

// writeStreamStall builds a 241 .ips: a JSON header line + a raw-DEFLATE body
// wrapping the given trace bytes.
func writeStreamStall(t *testing.T, trace []byte) string {
	t.Helper()
	hdr := `{"custom_headers":{"stalls":2,"sender":"CM-HLS","clientName":"Music","sessionID":"612E519B","type":"ABRTrace","serviceName":"app.music.subscription","version":"1.1","compression":"zlib"},"bug_type":"241","timestamp":"2025-07-24 16:34:19.00 -0600","os_version":"iPhone OS 26.0 (23A5297m)"}`
	var body bytes.Buffer
	fw, err := flate.NewWriter(&body, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := fw.Write(trace); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	fw.Close()

	path := filepath.Join(t.TempDir(), "amt.ips")
	if err := os.WriteFile(path, append([]byte(hdr+"\n"), body.Bytes()...), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	return path
}

func TestOpenStreamStall(t *testing.T) {
	trace := append([]byte("RHWN\x02\x00\x00\x00"), []byte("\x00\x00\x00\x00RRBA\x02\x00\x00\x00")...)
	ss, err := OpenStreamStall(writeStreamStall(t, trace), &Config{})
	if err != nil {
		t.Fatalf("OpenStreamStall: %v", err)
	}
	if ss.Header.BugType != "241" || ss.Header.BugTypeDesc != "AMTStreamingStallNetworkDiagnostics" {
		t.Errorf("bug type = %q / %q", ss.Header.BugType, ss.Header.BugTypeDesc)
	}
	if ss.Custom.ClientName != "Music" || ss.Custom.Stalls != 2 || ss.Custom.Sender != "CM-HLS" {
		t.Errorf("custom_headers = %+v", ss.Custom)
	}
	if ss.TraceSize != len(trace) {
		t.Errorf("TraceSize = %d, want %d", ss.TraceSize, len(trace))
	}
	if !contains(ss.TraceTags, "RHWN") || !contains(ss.TraceTags, "RRBA") {
		t.Errorf("TraceTags = %v, want RHWN + RRBA", ss.TraceTags)
	}
}

func TestStreamStallRender(t *testing.T) {
	prev := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prev })

	ss, err := OpenStreamStall(writeStreamStall(t, []byte("RHWNxxxxRRBAyyyy")), &Config{})
	if err != nil {
		t.Fatalf("OpenStreamStall: %v", err)
	}
	out := ss.String()
	for _, want := range []string{"AMTStreamingStallNetworkDiagnostics - Music", "Client", "Music", "ABRTrace", "tags: RHWN, RRBA"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\n%s", want, out)
		}
	}
}

// a body that isn't valid deflate must degrade to header-only, not error
func TestOpenStreamStallBadBody(t *testing.T) {
	hdr := `{"custom_headers":{"clientName":"Music"},"bug_type":"241","timestamp":"2025-07-24 16:34:19.00 -0600"}`
	path := filepath.Join(t.TempDir(), "amt.ips")
	if err := os.WriteFile(path, []byte(hdr+"\n\xff\xff\xff\xffnot-deflate"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	ss, err := OpenStreamStall(path, &Config{})
	if err != nil {
		t.Fatalf("OpenStreamStall should not hard-fail on a bad body: %v", err)
	}
	if ss.Custom.ClientName != "Music" {
		t.Errorf("header should still parse, got client %q", ss.Custom.ClientName)
	}
	if ss.TraceErr == "" {
		t.Error("expected TraceErr to be set for an undecompressable body")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
