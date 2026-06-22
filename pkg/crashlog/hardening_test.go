package crashlog

import (
	"encoding/json"
	"testing"
	"time"
)

// TestTimestampTolerant: an unrecognized or differently-shaped timestamp must
// never fail the surrounding document.
func TestTimestampTolerant(t *testing.T) {
	cases := []struct {
		in     string
		wantOK bool // whether it should parse to a non-zero time
	}{
		{`"2025-07-24 16:05:52.00 -0600"`, true}, // fractional seconds
		{`"2025-07-24 16:05:52 -0600"`, true},    // no fractional
		{`"2025-07-24T16:05:52Z"`, true},         // RFC3339
		{`"totally not a timestamp"`, false},     // garbage -> zero, no error
		{`""`, false},
		{`null`, false},
	}
	for _, c := range cases {
		var ts Timestamp
		if err := json.Unmarshal([]byte(c.in), &ts); err != nil {
			t.Errorf("Timestamp.Unmarshal(%s) errored (should never fail): %v", c.in, err)
			continue
		}
		gotNonZero := !time.Time(ts).IsZero()
		if gotNonZero != c.wantOK {
			t.Errorf("Timestamp.Unmarshal(%s): nonZero=%v, want %v", c.in, gotNonZero, c.wantOK)
		}
	}
}

func TestBinaryImageTolerant(t *testing.T) {
	// known source maps; unknown source is kept, not fatal
	var bi BinaryImage
	if err := json.Unmarshal([]byte(`["UUID-1", 4294967296, "P"]`), &bi); err != nil {
		t.Fatalf("valid image errored: %v", err)
	}
	if bi.Source != "Process" || bi.Base != 4294967296 {
		t.Errorf("got %+v, want Process/4294967296", bi)
	}
	var bu BinaryImage
	if err := json.Unmarshal([]byte(`["UUID-2", 1, "Z"]`), &bu); err != nil {
		t.Fatalf("unknown source must not error: %v", err)
	}
	if bu.Source != "Unknown(Z)" {
		t.Errorf("unknown source = %q, want Unknown(Z)", bu.Source)
	}
	// a short tuple errors but must not panic
	var bs BinaryImage
	if err := json.Unmarshal([]byte(`["UUID-3"]`), &bs); err == nil {
		t.Error("short binary image tuple should error, not silently succeed")
	}
}

func TestPanicFrameTolerant(t *testing.T) {
	var f PanicFrame
	if err := json.Unmarshal([]byte(`[2, 4660]`), &f); err != nil {
		t.Fatalf("numeric frame errored: %v", err)
	}
	if f.ImageIndex != 2 || f.ImageOffset != 4660 {
		t.Errorf("got %d/%d, want 2/4660", f.ImageIndex, f.ImageOffset)
	}
	// offset as a quoted hex string
	var fs PanicFrame
	if err := json.Unmarshal([]byte(`[2, "0x1234"]`), &fs); err != nil {
		t.Fatalf("string-offset frame errored: %v", err)
	}
	if fs.ImageOffset != 0x1234 {
		t.Errorf("string offset = %#x, want 0x1234", fs.ImageOffset)
	}
	// a trailing element Apple may append must be tolerated
	var fe PanicFrame
	if err := json.Unmarshal([]byte(`[2, 4660, 99]`), &fe); err != nil {
		t.Fatalf("frame with trailing element errored: %v", err)
	}
	if fe.ImageIndex != 2 || fe.ImageOffset != 4660 {
		t.Errorf("trailing-element frame got %d/%d", fe.ImageIndex, fe.ImageOffset)
	}
}

// TestThreadStateShortRegisters: rendering a thread state with fewer than 29
// registers (truncated/non-arm64) must not panic.
func TestThreadStateShortRegisters(t *testing.T) {
	for _, x := range [][]Register{nil, {}, {{Value: 1}, {Value: 2}}} {
		ts := ThreadState{X: x}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ThreadState.String panicked on %d registers: %v", len(x), r)
			}
		}()
		_ = ts.String()
	}
}

// TestPayloadTolueratesUnknownImageSource: a single unknown image source must
// not fail the whole payload decode.
func TestPayloadToleratesUnknownImageSource(t *testing.T) {
	const payload = `{
		"binaryImages": [
			["ff7119a7-f64d-305d-8135-7e6eb1c207d1", 4294967296, "P"],
			["ee0000a7-f64d-305d-8135-7e6eb1c207d1", 6979321856, "Z"]
		]
	}`
	var p IPSPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		t.Fatalf("payload with unknown image source failed to decode: %v", err)
	}
	if len(p.BinaryImages) != 2 || p.BinaryImages[1].Source != "Unknown(Z)" {
		t.Errorf("unexpected images: %+v", p.BinaryImages)
	}
}
