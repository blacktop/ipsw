package syms

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/codesign"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/testutil"
)

const (
	preferredEntitlements = `<plist version="1.0"><dict><key>slice</key><string>x1</string></dict></plist>`
	otherEntitlements     = `<plist version="1.0"><dict><key>slice</key><string>other</string></dict></plist>`
	emptyEntitlements     = `<plist version="1.0"><dict/></plist>`
)

func TestFilesystemFactsRetainAllSlicesAndSelections(t *testing.T) {
	x1 := testutil.MachoArch{CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64EX1, Entitlements: preferredEntitlements}
	e := testutil.MachoArch{CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64E, Entitlements: otherEntitlements}
	intel := testutil.MachoArch{CPU: types.CPUAmd64, SubCPU: types.CPUSubtypeX8664All, Entitlements: otherEntitlements}

	for _, tc := range []struct {
		name   string
		arches []testutil.MachoArch
	}{
		{"preferred first", []testutil.MachoArch{x1, e, intel}},
		{"preferred middle", []testutil.MachoArch{e, x1, intel}},
		{"preferred last", []testutil.MachoArch{intel, e, x1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			testutil.WriteMacho(t, filepath.Join(root, "tool"), tc.arches...)
			var output bytes.Buffer
			emitter := newJSONLEmitter(&output)
			visits := 0
			err := scanMachosInMount(root, "SystemOS", func(*scanImage) error {
				visits++
				return nil
			}, func(image *scanImage, m *macho.File) error {
				if len(image.Macho.Symbols) != 0 {
					t.Fatalf("facts observed enriched symbols: %+v", image.Macho.Symbols)
				}
				return emitter.facts(image, m)
			})
			if err != nil {
				t.Fatal(err)
			}
			if visits != 0 {
				t.Fatalf("UUID-less fixture produced %d legacy visits, want 0", visits)
			}

			lines := rawLines(t, output.Bytes())
			if len(lines) != len(tc.arches) {
				t.Fatalf("facts rows = %d, want %d", len(lines), len(tc.arches))
			}
			var machoSelected, entitlementSelected int
			for idx, raw := range lines {
				var row comparisonFactsLine
				if err := json.Unmarshal(raw, &row); err != nil {
					t.Fatal(err)
				}
				want := tc.arches[idx]
				if row.Occurrence.Path != "/tool" || row.Occurrence.VolumeLabel != "SystemOS" || row.Occurrence.UUID != "" {
					t.Fatalf("occurrence = %+v", row.Occurrence)
				}
				if row.Facts.CPU.Type != uint32(want.CPU) || row.Facts.CPU.Subtype != uint32(want.SubCPU) {
					t.Fatalf("row %d CPU = %+v, want %#x/%#x", idx, row.Facts.CPU, uint32(want.CPU), uint32(want.SubCPU))
				}
				if row.SliceSelection == nil || row.SliceSelection.Version != factsSliceSelectionVersion {
					t.Fatalf("row %d selection = %+v", idx, row.SliceSelection)
				}
				if row.SliceSelection.MachoReference {
					machoSelected++
					if idx != len(lines)-1 {
						t.Fatalf("Mach-O reference selected row %d, want last row", idx)
					}
				}
				if row.SliceSelection.EntitlementReference {
					entitlementSelected++
					if row.Facts.CPU.Type != uint32(types.CPUArm64) || row.Facts.CPU.Subtype != uint32(types.CPUSubtypeArm64EX1) {
						t.Fatalf("entitlement reference selected %+v", row.Facts.CPU)
					}
					if row.Facts.Entitlements.Status != "present" || !strings.Contains(string(row.Facts.Entitlements.Value), `"slice":"x1"`) {
						t.Fatalf("selected entitlement facts = %+v", row.Facts.Entitlements)
					}
				}
			}
			if machoSelected != 1 || entitlementSelected != 1 {
				t.Fatalf("selection counts = macho:%d entitlement:%d", machoSelected, entitlementSelected)
			}
		})
	}
}

func TestFilesystemFactsThinUnsignedAndMalformedEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, entitlements, status string
	}{
		{"thin signed", preferredEntitlements, "present"},
		{"thin empty", emptyEntitlements, "present"},
		{"thin unsigned", "", "absent"},
		{"thin malformed", "not a plist", "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			testutil.WriteMacho(t, filepath.Join(root, "tool"), testutil.MachoArch{
				CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64E, Entitlements: tc.entitlements,
			})
			var output bytes.Buffer
			emitter := newJSONLEmitter(&output)
			if err := scanMachosInMount(root, "filesystem", func(*scanImage) error { return nil }, emitter.facts); err != nil {
				t.Fatal(err)
			}
			lines := rawLines(t, output.Bytes())
			if len(lines) != 1 {
				t.Fatalf("facts rows = %d, want 1", len(lines))
			}
			var row comparisonFactsLine
			if err := json.Unmarshal(lines[0], &row); err != nil {
				t.Fatal(err)
			}
			if row.SliceSelection == nil || !row.SliceSelection.MachoReference || !row.SliceSelection.EntitlementReference {
				t.Fatalf("thin selection = %+v", row.SliceSelection)
			}
			if row.Facts.Entitlements.Status != tc.status {
				t.Fatalf("entitlement status = %q, want %q", row.Facts.Entitlements.Status, tc.status)
			}
			if tc.entitlements != "" {
				wantHash := fmt.Sprintf("%x", sha256.Sum256([]byte(tc.entitlements)))
				if row.Facts.Entitlements.SourceSHA256 != wantHash {
					t.Fatalf("source hash = %q, want %q", row.Facts.Entitlements.SourceSHA256, wantHash)
				}
			}
		})
	}
}

func TestFilesystemSliceValidationAndLegacySelection(t *testing.T) {
	x1 := syntheticSlice(types.CPUArm64, types.CPUSubtypeArm64EX1, preferredEntitlements, 1)
	intel := syntheticSlice(types.CPUAmd64, types.CPUSubtypeX8664All, otherEntitlements, 2)

	for _, tc := range []struct {
		name   string
		slices []*macho.File
	}{
		{"empty", nil},
		{"nil", []*macho.File{nil}},
		{"duplicate identity", []*macho.File{x1, syntheticSlice(types.CPUArm64, types.CPUSubtypeArm64EX1, otherEntitlements, 3)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := filesystemSliceSelections("/tool", tc.slices); err == nil {
				t.Fatal("invalid slice list was accepted")
			}
		})
	}

	var events []string
	visits := 0
	err := scanMachoSlices("/tool", "AppOS", []*macho.File{x1, intel}, func(image *scanImage) error {
		visits++
		events = append(events, "visit:"+image.Arch)
		return nil
	}, func(image *scanImage, _ *macho.File) error {
		events = append(events, "facts:"+image.Arch)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if visits != 1 || fmt.Sprint(events) != "[facts:arm64e_x1 facts:x86_64 visit:x86_64]" {
		t.Fatalf("events=%v visits=%d, want all facts before one last-slice visit", events, visits)
	}

	wantErr := errors.New("handler failed")
	visited := false
	err = scanMachoSlices("/tool", "AppOS", []*macho.File{x1, intel}, func(*scanImage) error {
		visited = true
		return nil
	}, func(image *scanImage, _ *macho.File) error {
		if image.Arch == "x86_64" {
			return wantErr
		}
		return nil
	})
	if !errors.Is(err, wantErr) || visited {
		t.Fatalf("handler error=%v visited=%t, want propagated error before legacy visit", err, visited)
	}
}

func syntheticSlice(cpu types.CPU, subCPU types.CPUSubtype, entitlements string, uuidByte byte) *macho.File {
	m := &macho.File{}
	m.CPU = cpu
	m.SubCPU = subCPU
	m.Loads = append(m.Loads, &macho.CodeSignature{CodeSignature: codesign.CodeSignature{Entitlements: entitlements}})
	uuid := types.UUID{uuidByte}
	m.Loads = append(m.Loads, &macho.UUID{UUIDCmd: types.UUIDCmd{LoadCmd: types.LC_UUID, Len: 24, UUID: uuid}})
	return m
}
