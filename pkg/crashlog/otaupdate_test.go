package crashlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/color"
)

const otaSample = `{"restore_payload_version":"Unknown","restore_type":"OTAUpdate","os_version":"23A5297m","itunes_version":"23A5297m","bug_type":"183","restore_error":"78","name":"iPhoneRestore"}
209b68600 : initializing new submission queue
209b68600 : MSU running in normal env
209b68600 : MobileSoftwareUpdateErrorDomain error 78 - Update finish took too long since apply finish event
`

func TestOpenOTAUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ota.ips")
	if err := os.WriteFile(path, []byte(otaSample), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	o, err := OpenOTAUpdate(path, &Config{})
	if err != nil {
		t.Fatalf("OpenOTAUpdate: %v", err)
	}
	if o.Header.BugType != "183" || o.BugTypeDesc != "OTASUpdate" {
		t.Errorf("bug type = %q / %q, want 183 / OTASUpdate", o.Header.BugType, o.BugTypeDesc)
	}
	if o.Header.RestoreError != "78" { // STRING, not int
		t.Errorf("RestoreError = %q, want \"78\"", o.Header.RestoreError)
	}
	if o.ErrorDomain != "MobileSoftwareUpdateErrorDomain" || o.ErrorCode != "78" {
		t.Errorf("extracted error = %q/%q, want MobileSoftwareUpdateErrorDomain/78", o.ErrorDomain, o.ErrorCode)
	}
	if !strings.Contains(o.ErrorMessage, "Update finish took too long") {
		t.Errorf("ErrorMessage = %q", o.ErrorMessage)
	}
	if len(o.Body) != 3 {
		t.Errorf("Body lines = %d, want 3", len(o.Body))
	}
}

func TestOTAUpdateRender(t *testing.T) {
	prev := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prev })

	path := filepath.Join(t.TempDir(), "ota.ips")
	if err := os.WriteFile(path, []byte(otaSample), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	o, err := OpenOTAUpdate(path, &Config{})
	if err != nil {
		t.Fatalf("OpenOTAUpdate: %v", err)
	}
	out := o.String()
	for _, want := range []string{
		"OTASUpdate - iPhoneRestore",
		"Restore Error  78",
		"MobileSoftwareUpdateErrorDomain error 78",
		"Update finish took too long",
		"initializing new submission queue",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\n%s", want, out)
		}
	}
}

// restore_error may arrive as a bare JSON number instead of a string; it must
// still parse and render the same.
func TestOpenOTAUpdateNumericError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ota.ips")
	if err := os.WriteFile(path, []byte(`{"bug_type":"183","restore_error":78,"name":"x"}`), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	o, err := OpenOTAUpdate(path, &Config{})
	if err != nil {
		t.Fatalf("OpenOTAUpdate with numeric restore_error: %v", err)
	}
	if o.Header.RestoreError != "78" {
		t.Errorf("RestoreError = %q, want \"78\"", o.Header.RestoreError)
	}
}

// header-only / no-body files must not panic or error
func TestOpenOTAUpdateHeaderOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ota.ips")
	if err := os.WriteFile(path, []byte(`{"bug_type":"183","restore_type":"OTAUpdate","name":"x"}`), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	o, err := OpenOTAUpdate(path, &Config{})
	if err != nil {
		t.Fatalf("OpenOTAUpdate header-only: %v", err)
	}
	if len(o.Body) != 0 {
		t.Errorf("expected empty body, got %d lines", len(o.Body))
	}
	_ = o.String() // must not panic
}
