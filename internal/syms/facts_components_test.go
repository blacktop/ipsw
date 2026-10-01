package syms

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/commands/mount"
	"github.com/blacktop/ipsw/internal/model"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

func componentTestInfo(manifests ...map[string]string) *info.Info {
	inf := testVolumeInfo(manifests...)
	inf.Plists.BuildManifest.SupportedProductTypes = []string{"Mac99,1"}
	for idx := range inf.Plists.BuildIdentities {
		inf.Plists.BuildIdentities[idx].Info = plist.IdentityInfo{DeviceClass: []string{"boarda", "boardb"}[idx], Variant: "Customer Erase Install (IPSW)"}
	}
	return inf
}

func TestFactsComponentsScanExactSelectedUnionOnce(t *testing.T) {
	for _, tc := range []struct {
		name, secondSystem, secondKernel string
		boards                           []string
	}{
		{"shared kernel and system", "system.dmg", "kernelcache.release.shared", []string{"BOARDB", "boarda"}},
		{"shared system distinct hardware kernels", "system.dmg", "kernelcache.release.other", []string{"boarda", "boardb"}},
		{"two system components", "other-system.dmg", "kernelcache.release.shared", []string{"boarda", "boardb"}},
		{"explicit subset", "other-system.dmg", "kernelcache.release.other", []string{"boarda"}},
		{"mixed fallback", "", "kernelcache.release.shared", []string{"boarda", "boardb"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			second := map[string]string{"KernelCache": tc.secondKernel, "OS": "other-os.dmg", "Ap,ExclaveOS": "exclave.dmg"}
			if tc.secondSystem != "" {
				second["Cryptex1,SystemOS"] = tc.secondSystem
			}
			inf := componentTestInfo(map[string]string{
				"KernelCache": "kernelcache.release.shared", "OS": "os.dmg",
				"Cryptex1,SystemOS": "system.dmg", "Cryptex1,AppOS": "empty-app.dmg",
			}, second)
			cfg := &JSONLConfig{Info: inf, Facts: true, FactsBoards: tc.boards, Kernel: true, DSC: true, FileSystem: true}
			collection, err := newFactsCollection(cfg, inf, factsSourceIdentity{SHA256: "source"})
			if err != nil {
				t.Fatal(err)
			}
			if collection.start.CollectionSchemaVersion != 4 || collection.start.Selection.RequestedSelector != "" {
				t.Fatalf("invalid v4 selection: %+v", collection.start)
			}
			wantBoards := []string{"boarda"}
			if len(tc.boards) == 2 {
				wantBoards = append(wantBoards, "boardb")
			}
			if !slices.Equal(collection.start.Selection.Boards, wantBoards) || len(collection.start.Selection.Identities) != len(wantBoards) {
				t.Fatalf("selected wrong board subset: %+v", collection.start.Selection)
			}
			var wire bytes.Buffer
			emitter := newJSONLEmitter(&wire)
			m := &macho.File{FileTOC: macho.FileTOC{FileHeader: types.FileHeader{CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64E}}}
			kernelCalls, mountCalls, dscCalls, walkCalls := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
			ops := factsScanOperations{
				kernel: func(one *factsCollection) error {
					paths := componentPaths(one.start.Selection, "KernelCache")
					if len(paths) != 1 {
						t.Fatalf("kernel invocation has %v paths", paths)
					}
					kernelCalls[paths[0]]++
					return emitter.facts(&scanImage{Kind: "kernel", ComponentPath: paths[0], Macho: &model.Macho{UUID: "KERNEL", Path: model.Path{Path: "kernel"}}}, m)
				},
				mount: func(component string, scan func(string) error) error {
					mountCalls[component]++
					return scan(component)
				},
				dsc: func(root string, visit scanVisitor, facts scanFactsVisitor) error {
					dscCalls[root]++
					if err := visit(&scanImage{Kind: "dsc", DSCUUID: "SAME-DSC", SharedRegionStart: 4096}); err != nil {
						return err
					}
					return facts(&scanImage{Kind: "dylib", DSCUUID: "SAME-DSC", Macho: &model.Macho{UUID: "DYLIB", Path: model.Path{Path: "/usr/lib/same.dylib"}}}, m)
				},
				machos: func(root, volume string, visit scanVisitor, facts scanFactsVisitor) error {
					walkCalls[root]++
					if root == "empty-app.dmg" {
						return nil
					}
					return facts(&scanImage{Kind: "macho", VolumeLabel: volume, Macho: &model.Macho{UUID: "FILE", Path: model.Path{Path: "/usr/bin/same"}}}, m)
				},
			}
			if err := runFactsComponents(collection, emitter.image, emitter.facts, ops); err != nil {
				t.Fatal(err)
			}
			wantKernel := map[string]int{"kernelcache.release.shared": 1}
			wantWalk := map[string]int{"os.dmg": 1, "system.dmg": 1, "empty-app.dmg": 1}
			wantDSC := map[string]int{"system.dmg": 1}
			if len(tc.boards) == 2 {
				wantKernel[tc.secondKernel] = 1
				wantWalk["other-os.dmg"], wantWalk["exclave.dmg"] = 1, 1
				if tc.secondSystem != "" {
					wantWalk[tc.secondSystem], wantDSC[tc.secondSystem] = 1, 1
				} else {
					wantDSC["other-os.dmg"] = 1
				}
			}
			if !reflect.DeepEqual(kernelCalls, wantKernel) || !reflect.DeepEqual(mountCalls, wantWalk) || !reflect.DeepEqual(walkCalls, wantWalk) || !reflect.DeepEqual(dscCalls, wantDSC) {
				t.Fatalf("wrong dispatch counts: kernels=%v mounts=%v walks=%v dsc=%v", kernelCalls, mountCalls, walkCalls, dscCalls)
			}
			footer, err := collection.completion(emitter)
			if err != nil {
				t.Fatal(err)
			}
			zeroComponent := false
			for _, row := range footer.Coverage {
				if row.Status != "successful" {
					continue
				}
				if len(row.ComponentRecords) != len(row.ComponentPaths) || len(row.ComponentPaths) == 0 {
					t.Fatalf("missing explicit component counts: %+v", row)
				}
				var total uint64
				for idx, count := range row.ComponentRecords {
					if count.Path != row.ComponentPaths[idx] {
						t.Fatalf("component counts out of order: %+v", row)
					}
					total += count.Records
					if count.Path == "empty-app.dmg" && count.Records == 0 {
						zeroComponent = true
					}
				}
				if total != row.Records {
					t.Fatalf("component counts do not reconcile: %+v", row)
				}
			}
			if !zeroComponent {
				t.Fatal("empty selected AppOS component omitted")
			}
			containers := map[string]bool{}
			for _, line := range rawLines(t, wire.Bytes()) {
				var record struct {
					Type          string                    `json:"type"`
					ComponentPath string                    `json:"component_path"`
					Occurrence    comparisonFactsOccurrence `json:"occurrence"`
				}
				if err := json.Unmarshal(line, &record); err != nil {
					t.Fatal(err)
				}
				switch record.Type {
				case "comparison_facts":
					if record.Occurrence.ComponentPath == "" {
						t.Fatalf("missing component context: %s", line)
					}
				case "dsc":
					if record.ComponentPath == "" || containers[record.ComponentPath] {
						t.Fatalf("wrong DSC container context: %s", line)
					}
					containers[record.ComponentPath] = true
					if !bytes.HasPrefix(line, []byte(`{"type":"dsc","uuid":"SAME-DSC","shared_region_start":4096,"component_path":`)) {
						t.Fatalf("legacy DSC header order changed: %s", line)
					}
				}
			}
			if len(containers) != len(wantDSC) {
				t.Fatalf("DSCs with equal UUID collapsed across components: %v", containers)
			}
		})
	}
}

func TestFactsBoardSelectionRejectsInvalidAndAmbiguousInputs(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*JSONLConfig)
	}{
		{"empty", func(c *JSONLConfig) { c.FactsBoards = []string{} }},
		{"duplicate normalized", func(c *JSONLConfig) { c.FactsBoards = []string{"boarda", "BOARDA"} }},
		{"unknown", func(c *JSONLConfig) { c.FactsBoards = []string{"missing"} }},
		{"too many", func(c *JSONLConfig) { c.FactsBoards = make([]string, 129) }},
		{"no facts", func(c *JSONLConfig) { c.Facts = false }},
		{"device", func(c *JSONLConfig) { c.Device = "Mac99,1" }},
		{"missing kernel", func(c *JSONLConfig) { delete(c.Info.Plists.BuildIdentities[0].Manifest, "KernelCache") }},
		{"missing system", func(c *JSONLConfig) { delete(c.Info.Plists.BuildIdentities[0].Manifest, "OS") }},
		{"empty path", func(c *JSONLConfig) {
			c.Info.Plists.BuildIdentities[0].Manifest["OS"] = plist.IdentityManifest{Info: map[string]any{"Path": ""}}
		}},
		{"ambiguous system", func(c *JSONLConfig) {
			other := c.Info.Plists.BuildIdentities[0]
			other.Manifest = map[string]plist.IdentityManifest{"OS": {Info: map[string]any{"Path": "other.dmg"}}}
			c.Info.Plists.BuildIdentities = append(c.Info.Plists.BuildIdentities, other)
		}},
		{"ambiguous kernel namespace", func(c *JSONLConfig) {
			other := c.Info.Plists.BuildIdentities[0]
			other.Manifest = map[string]plist.IdentityManifest{"KernelCache": {Info: map[string]any{"Path": "kernelcache.release.other"}}}
			c.Info.Plists.BuildIdentities = append(c.Info.Plists.BuildIdentities, other)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &JSONLConfig{Facts: true, FactsBoards: []string{"boarda"}, Kernel: true, DSC: true, FileSystem: true,
				Info: componentTestInfo(map[string]string{"OS": "os.dmg", "KernelCache": "kernelcache.release.shared"})}
			tc.edit(cfg)
			if err := ValidateFactsSelection(cfg); err == nil {
				t.Fatal("invalid selection accepted")
			}
		})
	}
}

func TestFactsComponentsDoNotCompleteAfterCleanupFailure(t *testing.T) {
	inf := componentTestInfo(map[string]string{"OS": "os.dmg"})
	collection, err := newFactsCollection(&JSONLConfig{Facts: true, FactsBoards: []string{"boarda"}, FileSystem: true}, inf, factsSourceIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	err = runFactsComponents(collection, func(*scanImage) error { return nil }, nil, factsScanOperations{
		mount: func(_ string, scan func(string) error) error {
			if err := scan("root"); err != nil {
				return err
			}
			return errors.New("detach failed")
		},
		machos: func(string, string, scanVisitor, scanFactsVisitor) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "detach failed") {
		t.Fatalf("cleanup failure lost: %v", err)
	}
	if _, err := collection.completion(newJSONLEmitter(&bytes.Buffer{})); err == nil {
		t.Fatal("completion accepted failed component cleanup")
	}
}

func TestFactsV4RejectsMissingOrDuplicateArchiveComponentBeforeOutput(t *testing.T) {
	for _, entries := range [][]string{{"other/os.dmg"}, {"os.dmg", "os.dmg"}} {
		var data bytes.Buffer
		writer := zip.NewWriter(&data)
		for _, name := range entries {
			if _, err := writer.Create(name); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		ipsw := filepath.Join(t.TempDir(), "synthetic.ipsw")
		if err := os.WriteFile(ipsw, data.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := &JSONLConfig{IPSW: ipsw, Info: componentTestInfo(map[string]string{"OS": "os.dmg"}),
			Facts: true, FactsBoards: []string{"boarda"}, FileSystem: true}
		// The command validates before it creates or truncates its output file.
		err := ValidateFactsSelection(cfg)
		if err == nil || !strings.Contains(err.Error(), "one exact archive member") {
			t.Fatalf("invalid archive passed pre-output validation: %v", err)
		}
		var output bytes.Buffer
		err = ScanJSONL(cfg, &output)
		if err == nil || !strings.Contains(err.Error(), "one exact archive member") || output.Len() != 0 {
			t.Fatalf("invalid archive produced output: err=%v stream=%s", err, output.String())
		}
	}
}

func TestFactsComponentMountCleanupRetainsOnlyAttachedImages(t *testing.T) {
	detachFailed := fmt.Errorf("%w: synthetic detach failure", utils.ErrMountCleanup)
	removeFailed := errors.New("synthetic backing file removal failure")
	acquireFailed := errors.New("synthetic acquisition failure")
	scanFailed := errors.New("synthetic scan failure")
	for _, tc := range []struct {
		name                         string
		acquireErr, unmountErr       error
		scanErr, wantErr             error
		borrowed, wantUnmount, keeps bool
	}{
		{name: "detached", wantUnmount: true},
		{name: "scan failure", scanErr: scanFailed, wantErr: scanFailed, wantUnmount: true},
		{name: "still attached", unmountErr: detachFailed, wantErr: utils.ErrMountCleanup, wantUnmount: true, keeps: true},
		{name: "backing file kept", unmountErr: removeFailed, wantErr: removeFailed, wantUnmount: true},
		{name: "acquisition failure", acquireErr: acquireFailed, wantErr: acquireFailed},
		{name: "borrowed", borrowed: true, keeps: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			var dir string
			acquire := func(private string) (*mount.Context, error) {
				dir = private
				image := filepath.Join(dir, "os.dmg")
				if err := os.WriteFile(image, []byte("synthetic image"), 0600); err != nil {
					t.Fatal(err)
				}
				if tc.acquireErr != nil {
					return nil, tc.acquireErr
				}
				return &mount.Context{DmgPath: image, MountPoint: "/synthetic/os", AlreadyMounted: tc.borrowed}, nil
			}
			unmounted := false
			unmount := func(*mount.Context) error {
				unmounted = true
				return tc.unmountErr
			}
			err := mountFactsComponent(acquire, unmount, func(string) error { return tc.scanErr })
			switch {
			case tc.borrowed:
				if err == nil || !strings.Contains(err.Error(), "already mounted") {
					t.Fatalf("borrowed mount accepted: %v", err)
				}
			case tc.wantErr == nil:
				if err != nil {
					t.Fatal(err)
				}
			case !errors.Is(err, tc.wantErr):
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if unmounted != tc.wantUnmount {
				t.Fatalf("unmount called = %t, want %t", unmounted, tc.wantUnmount)
			}
			if _, statErr := os.Stat(dir); (statErr == nil) != tc.keeps {
				t.Fatalf("component dir retained = %t, want %t", statErr == nil, tc.keeps)
			}
		})
	}
}
