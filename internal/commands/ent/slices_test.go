package ent

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apex/log"
	"github.com/apex/log/handlers/text"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/codesign"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/testutil"
)

func fakeSlice(cpu types.CPU, sub types.CPUSubtype, entitlements string) *macho.File {
	m := &macho.File{}
	m.CPU = cpu
	m.SubCPU = sub
	if entitlements != "" {
		m.Loads = append(m.Loads, &macho.CodeSignature{
			CodeSignature: codesign.CodeSignature{Entitlements: entitlements},
		})
	}
	return m
}

func TestPreferredSliceIgnoresFatOrder(t *testing.T) {
	x1 := fakeSlice(types.CPUArm64, types.CPUSubtypeArm64EX1, "<x1/>")
	e := fakeSlice(types.CPUArm64, types.CPUSubtypeArm64E, "<x1/>")
	plain := fakeSlice(types.CPUArm64, types.CPUSubtypeArm64All, "<x1/>")
	intel := fakeSlice(types.CPUAmd64, types.CPUSubtypeX8664All, "<x1/>")

	cases := map[string][]*macho.File{
		"x1 last":         {intel, e, x1},
		"x1 first":        {x1, e, intel},
		"x1 middle":       {e, x1, plain},
		"intel subtype 3": {x1, intel},
	}
	for name, slices := range cases {
		if got := PreferredSlice("bin", slices); got != x1 {
			t.Errorf("%s: picked %s, want ARM64e_X1", name, sliceName(got))
		}
	}
	if got := PreferredSlice("bin", []*macho.File{intel, plain, e}); got != e {
		t.Errorf("without x1: picked %s, want ARM64e", sliceName(got))
	}
	if got := PreferredSlice("bin", []*macho.File{intel, plain}); got != plain {
		t.Errorf("without arm64e: picked %s, want ARM64", sliceName(got))
	}
	if got := PreferredSlice("bin", []*macho.File{intel}); got != intel {
		t.Errorf("intel only: picked %s, want x86_64", sliceName(got))
	}
}

func TestPreferredSliceWarnsOnDisagreement(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Log
	log.Log = &log.Logger{Handler: text.New(&buf), Level: log.WarnLevel}
	t.Cleanup(func() { log.Log = prev })

	e := fakeSlice(types.CPUArm64, types.CPUSubtypeArm64E, "<old/>")
	x1 := fakeSlice(types.CPUArm64, types.CPUSubtypeArm64EX1, "<new/>")
	if got := PreferredSlice("/usr/bin/foo", []*macho.File{e, x1}); got != x1 {
		t.Fatalf("picked %s, want ARM64e_X1", sliceName(got))
	}
	if !strings.Contains(buf.String(), "entitlements differ between ARM64e and ARM64e_X1 slices of /usr/bin/foo") {
		t.Fatalf("expected disagreement warning, got: %q", buf.String())
	}

	buf.Reset()
	same := fakeSlice(types.CPUArm64, types.CPUSubtypeArm64E, "<new/>")
	PreferredSlice("/usr/bin/foo", []*macho.File{same, x1})
	if buf.Len() != 0 {
		t.Fatalf("unexpected warning for matching slices: %q", buf.String())
	}
}

func TestPreferredSliceWarnsOnLaunchConstraintDisagreement(t *testing.T) {
	for _, encoding := range []string{"XML", "DER", "no entitlements"} {
		for _, constraint := range []struct {
			name string
			set  func(*macho.CodeSignature, []byte)
		}{
			{"self", func(cs *macho.CodeSignature, data []byte) { cs.LaunchConstraintsSelf = data }},
			{"parent", func(cs *macho.CodeSignature, data []byte) { cs.LaunchConstraintsParent = data }},
			{"responsible", func(cs *macho.CodeSignature, data []byte) { cs.LaunchConstraintsResponsible = data }},
		} {
			for _, tc := range []struct {
				name string
				data []byte
				warn bool
			}{
				{"different", []byte{0x30, 0x03, 0x02, 0x01, 0x02}, true},
				{"missing", nil, true},
				{"identical", []byte{0x30, 0x03, 0x02, 0x01, 0x01}, false},
			} {
				t.Run(encoding+"/"+constraint.name+"/"+tc.name, func(t *testing.T) {
					var buf bytes.Buffer
					prev := log.Log
					log.Log = &log.Logger{Handler: text.New(&buf), Level: log.WarnLevel}
					t.Cleanup(func() { log.Log = prev })

					e := fakeSlice(types.CPUArm64, types.CPUSubtypeArm64E, "<same/>")
					x1 := fakeSlice(types.CPUArm64, types.CPUSubtypeArm64EX1, "<same/>")
					for _, m := range []*macho.File{e, x1} {
						if encoding != "XML" {
							m.CodeSignature().Entitlements = ""
						}
						if encoding == "DER" {
							m.CodeSignature().EntitlementsDER = []byte{0x30, 0x00}
						}
					}
					// Synthetic opaque DER blobs: divergence compares bytes without decoding.
					constraint.set(x1.CodeSignature(), []byte{0x30, 0x03, 0x02, 0x01, 0x01})
					constraint.set(e.CodeSignature(), tc.data)
					for _, slices := range [][]*macho.File{{e, x1}, {x1, e}} {
						buf.Reset()
						if got := PreferredSlice("/usr/bin/foo", slices); got != x1 {
							t.Fatalf("picked %s, want ARM64e_X1", sliceName(got))
						}
						warned := strings.Contains(buf.String(), "entitlements differ between ARM64e and ARM64e_X1 slices of /usr/bin/foo")
						if warned != tc.warn {
							t.Errorf("warning = %t, want %t; log: %q", warned, tc.warn, buf.String())
						}
					}
				})
			}
		}
	}
}

func TestPreferredSliceBreaksRankTies(t *testing.T) {
	for _, tc := range []struct {
		name        string
		want, other *macho.File
	}{
		{"x1 subtypes", fakeSlice(types.CPUArm64, types.CPUSubtypeArm64EX1, "<new/>"), fakeSlice(types.CPUArm64, types.CPUSubtypeArm64X1, "<old/>")},
		{"x1 subtypes with features", fakeSlice(types.CPUArm64, types.CPUSubtypeArm64EX1, "<new/>"), fakeSlice(types.CPUArm64, types.CPUSubtypeArm64X1|types.CpuSubtypeLib64, "<old/>")},
		{"other CPUs", fakeSlice(types.CPUAmd64, types.CPUSubtypeX8664All, "<new/>"), fakeSlice(types.CPUI386, types.CPUSubtypeI386All, "<old/>")},
		{"other subtypes", fakeSlice(types.CPUAmd64, types.CPUSubtypeX86_64H, "<new/>"), fakeSlice(types.CPUAmd64, types.CPUSubtypeX8664All, "<old/>")},
		{"feature bits", fakeSlice(types.CPUArm64, types.CPUSubtypeArm64E|types.CpuSubtypeLib64, "<new/>"), fakeSlice(types.CPUArm64, types.CPUSubtypeArm64E, "<old/>")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, slices := range [][]*macho.File{{tc.other, tc.want}, {tc.want, tc.other}} {
				if got := PreferredSlice("bin", slices); got != tc.want {
					t.Errorf("picked CPU=%#x subtype=%#x, want CPU=%#x subtype=%#x", uint32(got.CPU), got.SubCPU, uint32(tc.want.CPU), tc.want.SubCPU)
				}
			}
		})
	}
}

func TestEntitlementScanPathsIgnoreFatOrder(t *testing.T) {
	const want = `<plist version="1.0"><dict><key>synthetic.preferred</key><true/></dict></plist>`
	const other = `<plist version="1.0"><dict><key>synthetic.other</key><true/></dict></plist>`
	x1 := testutil.MachoArch{CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64EX1, Entitlements: want}
	e := testutil.MachoArch{CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64E, Entitlements: other}
	intel := testutil.MachoArch{CPU: types.CPUAmd64, SubCPU: types.CPUSubtypeX8664All, Entitlements: other}
	for _, arches := range [][]testutil.MachoArch{{x1, e, intel}, {intel, x1, e}, {e, intel, x1}, {x1}} {
		root := t.TempDir()
		path := filepath.Join(root, "tool")
		testutil.WriteMacho(t, path, arches...)
		db, err := GetDatabase(&Config{Folder: root, Database: filepath.Join(t.TempDir(), "ents.gz")})
		if err != nil {
			t.Fatal(err)
		}
		if got := db["/tool"]; got != want {
			t.Errorf("GetDatabase = %q, want %q", got, want)
		}
		// Capture the actual --fs output; its filter must see the preferred slice.
		out, err := os.CreateTemp(t.TempDir(), "stdout")
		if err != nil {
			t.Fatal(err)
		}
		func() {
			stdout := os.Stdout
			os.Stdout = out
			defer func() { os.Stdout = stdout }()
			err = SearchFilesystemEntitlements(nil, []string{root}, FilesystemQuery{Has: []string{"synthetic.preferred"}, FileOnly: true, Format: "jsonl"})
		}()
		if closeErr := out.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if err != nil {
			t.Fatal(err)
		}
		output, err := os.ReadFile(out.Name())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(output), path) {
			t.Errorf("SearchFilesystemEntitlements missed preferred slice: %q", output)
		}
	}
}

func TestFileEntitlementsSkipsNonMacho(t *testing.T) {
	path := t.TempDir() + "/plain.txt"
	if err := os.WriteFile(path, []byte("not a mach-o"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fileEntitlements(path, &Config{}); err != errNotMacho {
		t.Fatalf("got %v, want errNotMacho", err)
	}
}
