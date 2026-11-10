package fairplay

import (
	"errors"
	"strings"
	"testing"
)

func TestDecryptIPARejectsInvalidPaths(t *testing.T) {
	for _, path := range []string{"", "ipa\x00suffix", strings.Repeat("p", offlinePathMax+1)} {
		for position := range 3 {
			paths := [3]string{"fixture.ipa", "authorization.fpauth", "new-output"}
			paths[position] = path
			if _, err := DecryptIPA(paths[0], paths[1], paths[2]); !errors.Is(err, ErrOfflineArgument) {
				t.Fatalf("path position %d: expected invalid argument, got %v", position, err)
			}
		}
	}
}

func TestValidAuthorizationChecksEnvelope(t *testing.T) {
	valid := append([]byte("FPAUTH\x00\x00\x00\x00\x00\x01\x00\x00\x00\x04FAKEID"), "TEST"...)
	if !ValidAuthorization(valid) {
		t.Fatal("well-formed envelope was rejected")
	}
	mutate := func(index int, value byte) []byte {
		data := append([]byte(nil), valid...)
		data[index] = value
		return data
	}
	for name, data := range map[string][]byte{
		"empty":           nil,
		"header only":     valid[:authorizationHeaderBytes],
		"wrong magic":     mutate(0, 'X'),
		"wrong version":   mutate(11, 2),
		"length too long": mutate(15, 5),
		"truncated":       valid[:len(valid)-1],
		"trailing bytes":  append(append([]byte(nil), valid...), 0),
	} {
		if ValidAuthorization(data) {
			t.Fatalf("%s: malformed envelope was accepted", name)
		}
	}
}

func TestOfflineStatusUsesNeutralErrors(t *testing.T) {
	expected := []error{nil, ErrOfflineArgument, ErrLicenseAbsent, ErrOfflineUnsupported,
		ErrOfflinePermission, ErrOfflineIO, ErrOfflineProcessing, ErrOfflinePanic, ErrOfflineBuffer}
	for status, want := range expected {
		if got := offlineStatus(int32(status)); !errors.Is(got, want) {
			t.Fatalf("status %d: got %v, want %v", status, got, want)
		}
	}
	if err := offlineStatus(99); err == nil {
		t.Fatal("unknown status must fail")
	}
}
