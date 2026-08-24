package download

import (
	"encoding/json"
	"testing"

	internal "github.com/blacktop/ipsw/internal/download"
)

func TestWikiOTARequestIncludesSHA1(t *testing.T) {
	firmware := internal.WikiFirmware{
		URL:      "https://example.invalid/update.zip",
		Sha1Hash: "0123456789abcdef0123456789abcdef01234567",
	}
	request := wikiOTARequest(firmware, "/tmp/update.zip")
	if request.URL != firmware.URL || request.DestName != "/tmp/update.zip" {
		t.Fatalf("request routing = %#v", request)
	}
	if request.SHA1 != firmware.Sha1Hash {
		t.Fatalf("request SHA-1 = %q, want %q", request.SHA1, firmware.Sha1Hash)
	}
}

func TestAppleDBRequestIncludesAvailableDigests(t *testing.T) {
	var source internal.OsFileSource
	if err := json.Unmarshal([]byte(`{"hashes":{"sha1":"0123456789abcdef0123456789abcdef01234567","sha2-256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}`), &source); err != nil {
		t.Fatal(err)
	}
	request := appleDBRequest(source, "https://example.invalid/restore.ipsw", "/tmp/restore.ipsw")
	if request.URL != "https://example.invalid/restore.ipsw" || request.DestName != "/tmp/restore.ipsw" {
		t.Fatalf("request routing = %#v", request)
	}
	if request.SHA1 != source.Hashes.SHA1 || request.SHA256 != source.Hashes.SHA256 {
		t.Fatalf("request digests = SHA1 %q SHA256 %q", request.SHA1, request.SHA256)
	}
}
