package dyld

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

func TestSystemOSAmbiguityDoesNotFallBackToFilesystem(t *testing.T) {
	i := &info.Info{Plists: &plist.Plists{BuildManifest: &plist.BuildManifest{}}}
	for _, path := range []string{"first.dmg", "second.dmg"} {
		i.Plists.BuildIdentities = append(i.Plists.BuildIdentities, plist.BuildIdentity{Manifest: map[string]plist.IdentityManifest{
			"Cryptex1,SystemOS": {Info: map[string]any{"Path": path}},
			"OS":                {Info: map[string]any{"Path": "filesystem.dmg"}},
		}})
	}
	if path, err := dmgPathForDscStep(i, SystemOSDscDMG); err == nil || path != "" || !strings.Contains(err.Error(), "multiple SystemOS") {
		t.Fatalf("ambiguous SystemOS resolved to %q, %v", path, err)
	}
	for idx := range i.Plists.BuildIdentities {
		delete(i.Plists.BuildIdentities[idx].Manifest, "Cryptex1,SystemOS")
	}
	if path, err := dmgPathForDscStep(i, SystemOSDscDMG); err != nil || path != "filesystem.dmg" {
		t.Fatalf("legacy filesystem fallback = %q, %v", path, err)
	}
}

func TestNumberedArm64eCacheSelection(t *testing.T) {
	for _, variant := range []string{"arm64e_x1", "arm64e_x2", "arm64e_x12"} {
		for _, suffix := range []string{"", ".01", ".79.dyldlinkedit", ".symbols"} {
			path := "System/Library/dyld/dyld_shared_cache_" + variant + suffix
			if !dscArchRegex([]string{variant}, false, false).MatchString(path) {
				t.Fatalf("missed %s", path)
			}
			if dscArchRegex([]string{"arm64e"}, false, false).MatchString(path) {
				t.Fatalf("generic arch selected distinct variant %s", path)
			}
		}
		if dscArchRegex([]string{variant}, false, false).MatchString("System/Library/dyld/dyld_shared_cache_arm64e") {
			t.Fatal("numbered selector matched generic cache")
		}
		for _, arches := range [][]string{nil, {variant}} {
			if !RemoteCryptexPattern(arches).MatchString("cryptex-system-" + variant) {
				t.Fatalf("OTA discovery missed numbered variant for %v", arches)
			}
		}
	}
}

func TestArm64eX1Magic(t *testing.T) {
	// A synthetic header with no mappings/images exercises both NewFile's magic
	// validation and parseCache's validation; it contains no real device data.
	var header CacheHeader
	copy(header.Magic[:], "dyld_v1arm64ex1")
	header.UUID[0] = 1
	header.MappingOffset = uint32(binary.Size(header))
	header.CodeSignatureOffset = uint64(binary.Size(header))
	header.CodeSignatureSize = 12
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&data, binary.BigEndian, []uint32{0xfade0cc0, 12, 0}); err != nil {
		t.Fatal(err)
	}
	f, err := NewFile(bytes.NewReader(data.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !f.IsArm64() || !f.Is64bit() {
		t.Fatal("x1 not recognized as a 64-bit ARM cache")
	}
}
