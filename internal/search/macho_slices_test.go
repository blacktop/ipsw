package search_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/commands/ent"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/testutil"
)

func TestMachoWalkersSelectSlices(t *testing.T) {
	x1 := testutil.MachoArch{CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64EX1, Entitlements: "<preferred/>"}
	x1Plain := testutil.MachoArch{CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64X1, Entitlements: "<other/>"}
	intel := testutil.MachoArch{CPU: types.CPUAmd64, SubCPU: types.CPUSubtypeX8664All, Entitlements: "<other/>"}
	for _, arches := range [][]testutil.MachoArch{{x1, x1Plain, intel}, {intel, x1, x1Plain}, {x1Plain, intel, x1}, {x1}, {{CPU: types.CPUArm64}}} {
		root := t.TempDir()
		path := filepath.Join(root, "tool")
		testutil.WriteMacho(t, path, arches...)
		for _, walk := range []struct {
			name, key string
			run       func(string, func(string, *macho.File) error, ...search.MachoSliceSelector) error
		}{
			{"folder", path, search.ForEachMacho},
			{"mount", "/tool", search.ForEachMachoInMount},
		} {
			for _, selector := range []search.MachoSliceSelector{nil, ent.PreferredSlice} {
				want := arches[len(arches)-1].Entitlements
				if selector != nil && len(arches) > 1 {
					want = x1.Entitlements
				}
				calls := 0
				if err := walk.run(root, func(key string, m *macho.File) error {
					calls++
					got := ""
					if cs := m.CodeSignature(); cs != nil {
						got = cs.Entitlements
					}
					if key != walk.key || got != want {
						t.Errorf("%s: got (%q, %q), want (%q, %q)", walk.name, key, got, walk.key, want)
					}
					return nil
				}, selector); err != nil {
					t.Fatal(err)
				}
				if calls != 1 {
					t.Errorf("%s: got %d calls, want 1", walk.name, calls)
				}
			}
		}
	}
}

func TestForEachMachoSlicesRetainsFatOrderAndPropagatesErrors(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tool")
	testutil.WriteMacho(t, path,
		testutil.MachoArch{CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64EX1},
		testutil.MachoArch{CPU: types.CPUAmd64, SubCPU: types.CPUSubtypeX8664All})
	wantErr := errors.New("stop")
	calls := 0
	err := search.ForEachMachoSlices(root, func(gotPath string, slices []*macho.File) error {
		calls++
		if gotPath != path || len(slices) != 2 {
			t.Fatalf("got path=%q slices=%d, want path=%q slices=2", gotPath, len(slices), path)
		}
		if slices[0].CPU != types.CPUArm64 || slices[1].CPU != types.CPUAmd64 {
			t.Fatalf("slice order = [%s, %s], want [arm64, amd64]", slices[0].CPU, slices[1].CPU)
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) || calls != 1 {
		t.Fatalf("error=%v calls=%d, want stop and one call", err, calls)
	}
}

func TestMachoMultiWalkSelectsPerHandler(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b"} {
		testutil.WriteMacho(t, filepath.Join(root, name),
			testutil.MachoArch{CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64EX1, Entitlements: "<preferred/>"},
			testutil.MachoArch{CPU: types.CPUAmd64, SubCPU: types.CPUSubtypeX8664All, Entitlements: "<last/>"})
	}
	wantErr := errors.New("failed handler")
	calls := make(map[string]int)
	handler := func(name, want string) search.MachoScanHandler {
		return func(path string, m *macho.File) error {
			calls[name]++
			if path != "/a" && path != "/b" {
				t.Errorf("unexpected mount-relative path: %q", path)
			}
			if got := m.CodeSignature().Entitlements; got != want {
				t.Errorf("%s: entitlements = %q, want %q", name, got, want)
			}
			if name == "failing" {
				return wantErr
			}
			return nil
		}
	}
	err := search.ForEachMachoInMountMulti(root, []search.NamedMachoScanHandler{
		{Task: "failing", Select: ent.PreferredSlice, Handle: handler("failing", "<preferred/>")},
		{Task: "entitlements", Select: ent.PreferredSlice, Handle: handler("entitlements", "<preferred/>")},
		{Task: "machos", Handle: handler("machos", "<last/>")},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if calls["failing"] != 1 || calls["entitlements"] != 2 || calls["machos"] != 2 {
		t.Fatalf("unexpected calls after per-handler failure: %v", calls)
	}
}
