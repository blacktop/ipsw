package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testMobileDeviceSession struct {
	root              string
	rootErr, closeErr error
	closed            int
	typ               string
}

func (s *testMobileDeviceSession) Root(typ string) (string, error) {
	s.typ = typ
	return s.root, s.rootErr
}
func (s *testMobileDeviceSession) Close() error { s.closed++; return s.closeErr }

func TestListMobileDevices(t *testing.T) {
	for _, layout := range []string{
		"System/Library/CoreServices/CoreTypes.bundle/Contents/Library/MobileDevices.bundle/Info.plist",
		"System/Library/Templates/Data/System/Library/CoreServices/CoreTypes.bundle/Contents/Library/MobileDevices.bundle/Contents/Info.plist",
		"root/System/Library/CoreServices/CoreTypes.bundle/Contents/Library/MobileDevices.bundle/Info.plist",
	} {
		t.Run(layout, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, layout)
			if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
				t.Fatal(err)
			}
			const data = `<?xml version="1.0"?><plist version="1.0"><dict><key>UTExportedTypeDeclarations</key><array><dict><key>UTTypeIdentifier</key><string>test.phone</string><key>UTTypeDescription</key><string>Synthetic Phone</string><key>UTTypeTagSpecification</key><dict><key>com.apple.device-model-code</key><string>Phone99,1</string></dict></dict></array></dict></plist>`
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			session := &testMobileDeviceSession{root: root}
			var output bytes.Buffer
			if err := listMobileDevices(session, &output); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"test.phone:", "Synthetic Phone", "Phone99,1"} {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("output %q missing %q", output.String(), want)
				}
			}
			if session.typ != "fs" || session.closed != 1 {
				t.Fatalf("session = %+v", session)
			}
		})
	}
}

func TestListMobileDevicesClosesOnErrors(t *testing.T) {
	mountErr := errors.New("synthetic mount failure")
	closeErr := errors.New("synthetic close failure")
	session := &testMobileDeviceSession{rootErr: mountErr, closeErr: closeErr}
	err := listMobileDevices(session, &bytes.Buffer{})
	if !errors.Is(err, mountErr) || !errors.Is(err, closeErr) || session.closed != 1 {
		t.Fatalf("error = %v, closed = %d", err, session.closed)
	}

	root := t.TempDir()
	bundle := filepath.Join(root, "System/Library/CoreServices/CoreTypes.bundle/Contents/Library/MobileDevices.bundle")
	if err := os.MkdirAll(bundle, 0750); err != nil {
		t.Fatal(err)
	}
	session = &testMobileDeviceSession{root: root, closeErr: closeErr}
	err = listMobileDevices(session, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "failed to read Info.plist") || !errors.Is(err, closeErr) || session.closed != 1 {
		t.Fatalf("error = %v, closed = %d", err, session.closed)
	}
}
