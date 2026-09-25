package dyld

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// TestPrebuiltDigest records the complete parsed output for an opt-in real cache.
func TestPrebuiltDigest(t *testing.T) {
	path := os.Getenv("DSC")
	if path == "" {
		t.Skip("set DSC and DIGEST_OUT to compare real-cache prebuilt loaders")
	}
	output := os.Getenv("DIGEST_OUT")
	if output == "" {
		t.Fatal("DIGEST_OUT is required when DSC is set")
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out, err := os.Create(output)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			t.Error(err)
		}
	}()
	write := func(path string, value any) {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if _, err := fmt.Fprintf(out, "%s\t%x\n", path, sha256.Sum256(data)); err != nil {
			t.Fatal(err)
		}
	}
	for _, img := range f.Images {
		loader, err := f.GetDylibPrebuiltLoader(img.Name)
		if err != nil {
			t.Fatalf("%s: %v", img.Name, err)
		}
		write(img.Name, loader)
	}
	if err := f.ForEachLaunchLoaderSet(func(path string, set *PrebuiltLoaderSet) { write(path, set) }); err != nil {
		t.Fatal(err)
	}
}
