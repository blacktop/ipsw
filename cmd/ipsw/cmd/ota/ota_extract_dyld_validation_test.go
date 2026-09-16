package ota

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/ota"
)

func TestExtractDSCReportsEachFamily(t *testing.T) {
	const system = "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e"
	const driverKit = "out/24G720__MacOS/System/DriverKit/System/Library/dyld/dyld_shared_cache_arm64e"
	const intel = "out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_x86_64"
	for _, tt := range []struct {
		name                     string
		files, broken, wantPaths []string
	}{
		{"both valid", []string{system, driverKit}, nil, nil},
		{"broken System valid DriverKit", []string{system, driverKit}, []string{system}, []string{system}},
		{"both broken", []string{system, driverKit}, []string{system, driverKit}, []string{system, driverKit}},
		{"DriverKit sidecars only", []string{system, driverKit + ".01"}, nil, []string{driverKit}},
		{"System sidecars only", []string{system + ".01", driverKit}, nil, []string{system}},
		{"same directory different architectures", []string{system, intel}, []string{intel}, []string{intel}},
		{"sidecar before its primary", []string{system + ".01", system}, nil, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOpts()
			opts.ValidateFamily = func(path string) error {
				if !slices.Contains(tt.files, path) {
					t.Fatalf("validated non-primary %q", path)
				}
				if slices.Contains(tt.broken, path) {
					return errors.New("missing required subcache")
				}
				return nil
			}
			rep := extractDSC(&fakeDSCSource{payload: tt.files}, opts)
			if rep.Complete != (len(tt.wantPaths) == 0) || len(rep.Files) != len(tt.files) {
				t.Fatalf("report = %+v", rep)
			}
			// Decode the public JSON field, also pinning its report-relative form.
			data, err := json.Marshal(rep)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				Errors []struct{ Phase, Source, Path string }
			}
			if err := json.Unmarshal(data, &wire); err != nil {
				t.Fatal(err)
			}
			var paths, wantPaths []string
			for _, failure := range wire.Errors {
				if failure.Phase != string(ota.PhaseDSCValidation) || failure.Source != sourcePayloadV2 {
					t.Fatalf("unexpected failure: %+v", failure)
				}
				paths = append(paths, failure.Path)
			}
			for _, path := range tt.wantPaths {
				wantPaths = append(wantPaths, strings.TrimPrefix(path, "out/"))
			}
			slices.Sort(paths)
			slices.Sort(wantPaths)
			if !slices.Equal(paths, wantPaths) {
				t.Fatalf("error paths = %v, want %v", paths, wantPaths)
			}
		})
	}
}

func TestExtractDSCValidatesFamiliesAlongsideDiscoveryFailures(t *testing.T) {
	opts := testOpts()
	opts.Arches = []string{"arm64e", "x86_64"}
	opts.ValidateFamily = func(path string) error { return errors.New("missing subcache") }
	rep := extractDSC(&fakeDSCSource{payload: []string{
		"out/24G720__MacOS/System/Library/dyld/dyld_shared_cache_arm64e",
	}}, opts)
	if rep.Complete || len(rep.Errors) != 2 || rep.Errors[0].Phase != ota.PhaseDSCDiscovery || rep.Errors[1].Phase != ota.PhaseDSCValidation {
		t.Fatalf("report = %+v, want discovery and independent family validation failures", rep)
	}
}

func TestValidateDSCFamilySyntheticHeaders(t *testing.T) {
	for _, missing := range []bool{false, true} {
		name := "self-contained"
		if missing {
			name = "missing-subcache"
		}
		t.Run(name, func(t *testing.T) {
			var header dyld.CacheHeader
			copy(header.Magic[:], "dyld_v1arm64ex1")
			header.UUID[0] = 1
			header.MappingOffset = uint32(binary.Size(header))
			header.CodeSignatureOffset = uint64(binary.Size(header))
			header.CodeSignatureSize = 12
			var subcache struct {
				UUID          [16]byte
				CacheVMOffset uint64
				FileSuffix    [32]byte
			}
			if missing {
				// A well-formed subcache array isolates the absent file from
				// malformed-header handling in dyld.Open.
				header.SubCacheArrayCount = 1
				header.SubCacheArrayOffset = uint32(binary.Size(header)) + 12
				subcache.UUID[0] = 2
				copy(subcache.FileSuffix[:], ".01")
			}
			var data bytes.Buffer
			if err := binary.Write(&data, binary.LittleEndian, header); err != nil {
				t.Fatal(err)
			}
			if err := binary.Write(&data, binary.BigEndian, []uint32{0xfade0cc0, 12, 0}); err != nil {
				t.Fatal(err)
			}
			if missing {
				if err := binary.Write(&data, binary.LittleEndian, subcache); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(t.TempDir(), "dyld_shared_cache_arm64e_x1")
			if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			err := validateDSCFamily(path)
			if missing {
				if err == nil || !strings.Contains(err.Error(), path+".01") {
					t.Fatalf("missing subcache error = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
