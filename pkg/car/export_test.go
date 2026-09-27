package car

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportPlanIsDeferredAndRawPreservesCSI(t *testing.T) {
	csi := syntheticCSI(t, "sample", PixFmtARGB, OnePart, 2, 3, nil, []byte("invalid bitmap"))
	input := writeCatalog(t, syntheticCatalog(t, []syntheticRendition{{[]uint16{1}, csi}}, []renditionAttributeType{Identifier}))
	output := filepath.Join(t.TempDir(), "exports")
	a, err := Parse(input, &Config{MetadataOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	plan := a.PlanExport(output)
	if len(plan) != 1 || !plan[0].Deferred || plan[0].Status != "planned" || plan[0].Width != 2 || plan[0].Height != 3 {
		t.Fatalf("plan = %+v", plan)
	}
	var manifest bytes.Buffer
	if err := a.WriteManifest(&manifest, output); err != nil || !json.Valid(manifest.Bytes()) {
		t.Fatalf("manifest: %v, %q", err, manifest.String())
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) || a.ImageDB[0].Asset != nil {
		t.Fatal("planning performed export or decoding")
	}
	a, err = Parse(input, &Config{Raw: true, Export: true, Output: output})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(a.ImageDB[0].ExportPath)
	if err != nil || !bytes.Equal(data, csi) || !strings.HasSuffix(a.ImageDB[0].ExportPath, ".csi") {
		t.Fatalf("raw CSI export: %v", err)
	}
	if stats := a.Stats(); stats.Exported != 1 || stats.SelectedDeferred != 1 {
		t.Fatalf("raw stats = %+v", stats)
	}
}

func TestExportOrientAfterCropPreservesDepthAndProfile(t *testing.T) {
	atlas := image.NewNRGBA64(image.Rect(0, 0, 3, 3))
	for y := range 3 {
		for x := range 3 {
			atlas.SetNRGBA64(x, y, color.NRGBA64{R: uint16(1000 + x*200 + y*3000), A: 65535})
		}
	}
	link := referenceRendition(1, 2, linkRect{1, 0, 2, 1})
	link.Orientation = 6
	link.Selected = true
	a := Asset{
		KeyFormat: []renditionAttributeType{Identifier, Scale}, selectionReady: true,
		conf:    &Config{Export: true, Output: t.TempDir(), ApplyOrientation: true},
		ImageDB: []Rendition{link, {Key: []uint16{2, 0}, Asset: atlas, ColorSpace: DisplayP3, Width: 3, Height: 3}},
	}
	if err := resolveTestReferences(&a); err != nil || a.ImageDB[0].ResolveError != nil {
		t.Fatalf("resolve: %v, %v", err, a.ImageDB[0].ResolveError)
	}
	plan := a.PlanExport(a.conf.Output)
	if len(plan) != 1 || plan[0].Width != 1 || plan[0].Height != 2 || len(plan[0].Crops) != 1 || len(plan[0].SourceKey) != 2 {
		t.Fatalf("oriented crop plan = %+v", plan)
	}
	a.exportRenditions(a.indexRenditions())
	data, err := os.ReadFile(a.ImageDB[0].ExportPath)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil || img.Bounds() != image.Rect(0, 0, 1, 2) {
		t.Fatalf("oriented export: %v", err)
	}
	for y := range 2 {
		if got := color.NRGBA64Model.Convert(img.At(0, y)); got != atlas.NRGBA64At(1+y, 2) {
			t.Fatalf("pixel %d = %v", y, got)
		}
	}
	if !bytes.Contains(data, []byte("iCCP")) || a.ImageDB[0].ColorSpace != DisplayP3 {
		t.Fatal("reference export lost source profile")
	}
	if a.ImageDB[0].Asset.(image.Image).Bounds() != image.Rect(0, 0, 2, 1) || atlas.Bounds() != image.Rect(0, 0, 3, 3) {
		t.Fatal("orientation mutated reference source coordinates")
	}
}

func TestExportPlanIncludesFailuresAndHEVCOriginal(t *testing.T) {
	a := Asset{conf: &Config{}, ImageDB: []Rendition{
		{Key: []uint16{1}, RenditionName: "original", PixelFormat: PixFmtARGB, Compression: HEVC.String(), Deferred: true},
		{Key: []uint16{2}, RenditionName: "bad", PixelFormat: PixFmtARGB, DecodeError: fmt.Errorf("bad stream")},
		{Key: []uint16{3}, RenditionName: "future", PixelFormat: "????"},
	}}
	plan := a.PlanExport("output")
	if plan[0].Format != "heic" || plan[1].Status != "failed" || plan[2].Status != "unsupported" {
		t.Fatalf("plan = %+v", plan)
	}
	a.conf.Render = true
	if got := a.PlanExport("output")[0].Format; got != "png" {
		t.Fatalf("render plan extension = %s", got)
	}
	a.conf.ApplyOrientation = true
	a.ImageDB[0].Resources = []csiResource{{ID: MetaDataEXIFOrientationID, Data: []byte{6}}}
	if got := a.PlanExport("output")[0]; got.Status != "failed" || !strings.Contains(got.Error, "orientation resource") {
		t.Fatalf("malformed orientation silently ignored: %+v", got)
	}
}

func TestExportPlanReflectsCallerMutations(t *testing.T) {
	link := referenceRendition(1, 2, linkRect{0, 0, 1, 1})
	link.link.Layout = uint16(RawData)
	link.Attributes = map[string]uint16{Identifier.String(): 1}
	a := Asset{
		KeyFormat: []renditionAttributeType{Identifier, Scale},
		FacetKeyDB: map[string]renditionKeyToken{
			"z.caar": {Attributes: []renditionAttribute{{Name: uint16(Identifier), Value: 1}}},
			"a.caar": {Attributes: []renditionAttribute{{Name: uint16(Identifier), Value: 1}}},
		},
		ImageDB: []Rendition{link, {Key: []uint16{2, 0}, PixelFormat: PixFmtRawData}},
	}
	first := a.PlanExport("first")[0]
	if first.Status != "planned" || !strings.HasPrefix(filepath.Base(first.Path), "a-") ||
		len(first.SourceKey) != 2 || first.SourceKey[0] != 2 {
		t.Fatalf("initial plan = %+v", first)
	}
	// Public keys, formats and facets may all change between plans.
	a.KeyFormat = []renditionAttributeType{Scale, Identifier}
	a.ImageDB[0].Key = []uint16{0, 1}
	a.ImageDB[1].Key = []uint16{0, 2}
	delete(a.FacetKeyDB, "a.caar")
	a.ImageDB[0].ExportError = fmt.Errorf("synthetic write failure")
	second := a.PlanExport("second")[0]
	if second.Status != "failed" || second.Error != "synthetic write failure" ||
		!strings.HasPrefix(filepath.Base(second.Path), "z-") || second.SourceKey[1] != 2 ||
		filepath.Base(first.Path) == filepath.Base(second.Path) {
		t.Fatalf("plan reused stale state: %+v", second)
	}
	a.ImageDB[0].ExportError = nil
	a.ImageDB[0].ExportPath = filepath.Join("completed", "link.caar")
	var manifest bytes.Buffer
	if err := a.WriteManifest(&manifest, "third"); err != nil {
		t.Fatal(err)
	}
	var report struct{ Entries []ExportEntry }
	if err := json.Unmarshal(manifest.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if entry := report.Entries[0]; entry.Status != "exported" ||
		entry.Path != a.ImageDB[0].ExportPath || first.Status != "planned" || first.Key[0] != 1 {
		t.Fatalf("manifest or earlier snapshot changed: %+v; %+v", entry, first)
	}
}

func TestExportPlanKeepsManualDuplicateKeyBehavior(t *testing.T) {
	a := Asset{
		KeyFormat: []renditionAttributeType{Identifier, Scale},
		ImageDB: []Rendition{
			referenceRendition(1, 2, linkRect{0, 0, 1, 1}),
			{Key: []uint16{2, 0}, RenditionName: "atlas",
				PixelFormat: PixFmtARGB, ColorSpace: SRGB},
			{Key: []uint16{2, 0}, RenditionName: "atlas",
				PixelFormat: PixFmtARGB, ColorSpace: DisplayP3},
		},
	}
	plan := a.PlanExport("output")
	if len(plan) != 3 || plan[0].ColorSpace != DisplayP3.String() || plan[0].Error != "" ||
		plan[1].Path == plan[2].Path || !strings.HasSuffix(plan[2].Path, "-1.png") {
		t.Fatalf("manual duplicate keys lost last-target lookup or unique filenames: %+v", plan)
	}
}

func TestUnsupportedRenditionsRemainSeparateFromFailures(t *testing.T) {
	var items []syntheticRendition
	for i, layout := range []renditionLayoutType{ThinningPlaceholder, NamedContents, TextureRendition} {
		items = append(items, syntheticRendition{[]uint16{uint16(i + 1)},
			syntheticCSI(t, layout.String(), "", layout, 0, 0, nil, nil)})
	}
	items = append(items,
		syntheticRendition{[]uint16{4}, syntheticCSI(t, "broken", PixFmtARGB, OnePart, 1, 1, nil, nil)},
		syntheticRendition{[]uint16{5}, syntheticCSI(t, "valid", PixFmtRawData, RawData, 0, 0, nil, []byte("data"))},
	)
	input := writeCatalog(t, syntheticCatalog(t, items, []renditionAttributeType{Identifier}))
	for _, metadataOnly := range []bool{false, true} {
		a, err := Parse(input, &Config{MetadataOnly: metadataOnly, Export: !metadataOnly, Output: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		plan := a.PlanExport(a.conf.Output)
		for _, entry := range plan[:3] {
			if entry.Status != "unsupported" || entry.Error == "" || entry.Path != "" {
				t.Fatalf("unsupported rendition misclassified: %+v", entry)
			}
		}
		if !metadataOnly {
			if plan[3].Status != "failed" || plan[4].Status != "exported" {
				t.Fatalf("failure interrupted valid export: %+v", plan[3:])
			}
			if stats := a.Stats(); stats.DecodeFailures != 1 || stats.ExportFailures != 0 || stats.Exported != 1 {
				t.Fatalf("unsupported entries counted as failures: %+v", stats)
			}
		}
	}
}

func TestExportPlanUsesReferenceOutputFormatAndColorSpace(t *testing.T) {
	link := referenceRendition(1, 2, linkRect{0, 0, 1, 1})
	link.PixelFormat = PixFmtJPEG
	link.Selected = true
	a := Asset{KeyFormat: []renditionAttributeType{Identifier, Scale}, selectionReady: true,
		ImageDB: []Rendition{link, {Key: []uint16{2, 0}, PixelFormat: PixFmtJPEG, ColorSpace: DisplayP3, Width: 1, Height: 1}},
	}
	plan := a.PlanExport("output")
	if len(plan) != 1 || plan[0].Format != "png" || plan[0].ColorSpace != DisplayP3.String() {
		t.Fatalf("reference plan = %+v", plan)
	}
	a.ImageDB[1].PixelFormat = PixFmtRawData
	a.ImageDB[1].payload = []byte("bvx2compressed source")
	a.ImageDB[1].Deferred = true
	if got := a.PlanExport("output")[0]; got.ColorSpace != "" || len(got.Warnings) == 0 {
		t.Fatalf("reference plan hides deferred DATA format: %+v", got)
	}
	a.ImageDB[1].PixelFormat = PixFmtHEIF
	if got := a.PlanExport("output")[0].ColorSpace; got != SRGB.String() {
		t.Fatalf("rendered reference space = %s", got)
	}
}

func TestExportPlanKeepsRenderedReferenceColorSpace(t *testing.T) {
	link := referenceRendition(1, 2, linkRect{0, 0, 1, 1})
	link.Selected = true
	a := Asset{KeyFormat: []renditionAttributeType{Identifier, Scale}, selectionReady: true,
		conf: &Config{Render: true},
		ImageDB: []Rendition{link, {
			Key: []uint16{2, 0}, PixelFormat: PixFmtRawData, ColorSpace: SRGB, Width: 1, Height: 1,
			Asset: image.NewRGBA(image.Rect(0, 0, 1, 1)), payload: []byte("bvx2compressed source"),
		}},
	}
	if err := resolveTestReferences(&a); err != nil || a.ImageDB[0].ResolveError != nil {
		t.Fatalf("resolve: %v, %v", err, a.ImageDB[0].ResolveError)
	}
	plan := a.PlanExport("output")
	if len(plan) != 1 || plan[0].ColorSpace != SRGB.String() || len(plan[0].Warnings) != 0 || plan[0].Deferred {
		t.Fatalf("rendered reference plan = %+v", plan)
	}
}

func TestExportPlanSniffsUncompressedDATAForRendering(t *testing.T) {
	data := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="2" height="3"/>`)
	a := Asset{conf: &Config{Render: true}, ImageDB: []Rendition{
		{Key: []uint16{1}, PixelFormat: PixFmtRawData, payload: data, Deferred: true, ColorSpace: DisplayP3},
	}}
	plan := a.PlanExport("output")
	if plan[0].Format != "png" || plan[0].ColorSpace != SRGB.String() {
		t.Fatalf("DATA SVG plan = %+v", plan)
	}
	a.ImageDB[0].payload = []byte("bvx2compressed source")
	if got := a.PlanExport("output")[0]; len(got.Warnings) == 0 || !got.Deferred {
		t.Fatalf("compressed DATA plan hides uncertainty: %+v", got)
	}
}

func TestExportRenditionsSafeUniqueDeterministic(t *testing.T) {
	output := t.TempDir()
	names := []string{"../../escape", "/absolute", "a", "a.png", "A.PNG", "a_1", "..\\escape", "\x00\n", strings.Repeat("x", 300), "photo.png"}
	a := Asset{conf: &Config{Export: true, Output: output}}
	for i, name := range names {
		a.ImageDB = append(a.ImageDB, Rendition{RenditionName: name, Key: []uint16{uint16(i)}, PixelFormat: PixFmtRawData, Asset: []byte{byte(i)}})
	}
	a.exportRenditions(a.indexRenditions())
	paths := make(map[uint16]string)
	for i, rend := range a.ImageDB {
		if rend.ExportError != nil {
			t.Fatal(rend.ExportError)
		}
		if filepath.Dir(rend.ExportPath) != output {
			t.Fatalf("escaped output: %s", rend.ExportPath)
		}
		if len(filepath.Base(rend.ExportPath)) > 255 {
			t.Fatalf("filename too long: %s", rend.ExportPath)
		}
		paths[rend.Key[0]] = filepath.Base(rend.ExportPath)
		data, err := os.ReadFile(rend.ExportPath)
		if err != nil || len(data) != 1 || data[0] != byte(i) {
			t.Fatalf("file %d: data %v, error %v", i, data, err)
		}
	}
	if !strings.HasSuffix(a.ImageDB[len(names)-1].ExportPath, ".png") {
		t.Fatal("raw payload extension lost")
	}
	second := t.TempDir()
	a.conf.Output = second
	for i, j := 0, len(a.ImageDB)-1; i < j; i, j = i+1, j-1 {
		a.ImageDB[i], a.ImageDB[j] = a.ImageDB[j], a.ImageDB[i]
	}
	a.exportRenditions(a.indexRenditions())
	for _, rend := range a.ImageDB {
		if filepath.Base(rend.ExportPath) != paths[rend.Key[0]] {
			t.Fatal("filename depends on rendition order")
		}
	}
}

func TestExportReplacesSymlinkWithoutFollowingIt(t *testing.T) {
	output := t.TempDir()
	a := Asset{conf: &Config{Export: true, Output: output}, ImageDB: []Rendition{{RenditionName: "test", Key: []uint16{1}, PixelFormat: PixFmtRawData, Asset: []byte("first")}}}
	a.exportRenditions(a.indexRenditions())
	path := a.ImageDB[0].ExportPath
	if path == "" {
		t.Fatal(a.ImageDB[0].ExportError)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("protected"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	a.ImageDB[0].ExportPath = ""
	a.ImageDB = append(a.ImageDB, Rendition{RenditionName: "test", Key: []uint16{2}, PixelFormat: PixFmtRawData, Asset: []byte("second")})
	a.exportRenditions(a.indexRenditions())
	if a.ImageDB[0].ExportError != nil || a.ImageDB[0].ExportPath == "" {
		t.Fatal("existing symlink was not replaced")
	}
	if a.ImageDB[1].ExportPath == "" || a.ImageDB[1].ExportError != nil {
		t.Fatal("export stopped at failed rendition")
	}
	data, err := os.ReadFile(victim)
	if err != nil || string(data) != "protected" {
		t.Fatalf("victim changed: %q, %v", data, err)
	}
}

func TestExportStructuredMetadataTwice(t *testing.T) {
	a := Asset{conf: &Config{Export: true, Output: t.TempDir()}, ImageDB: []Rendition{
		{RenditionName: "color", Key: []uint16{1}, Asset: csiColor{NumberOfComponents: 2, Components: []float64{0.5, 1}}},
		{RenditionName: "sizes", Key: []uint16{2}, Asset: csiMultisizeImageSet{NImageSizes: 1, ImageSizes: []csiMultiImgSetImageSize{{Width: 32, Height: 64}}}},
	}}
	a.exportRenditions(a.indexRenditions())
	for i := range a.ImageDB {
		rend := &a.ImageDB[i]
		data, err := os.ReadFile(rend.ExportPath)
		if err != nil || !strings.HasSuffix(rend.ExportPath, ".json") || !json.Valid(data) {
			t.Fatalf("metadata export: %q, %v", rend.ExportPath, err)
		}
		rend.ExportPath = ""
	}
	a.exportRenditions(a.indexRenditions())
	for _, rend := range a.ImageDB {
		if rend.ExportError != nil || rend.ExportPath == "" {
			t.Fatal("repeat export failed")
		}
	}
}

func TestFailedExportPreservesOldFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset.png")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeRendition(path, struct{}{}, SRGB); err == nil {
		t.Fatal("accepted an unsupported asset")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "old" {
		t.Fatalf("failed write changed previous file: %q, %v", got, err)
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(files) != 1 {
		t.Fatalf("temporary file was left behind: %v, %v", files, err)
	}
}

func TestDrawingLayoutsRemainUnsupported(t *testing.T) {
	var items []syntheticRendition
	for _, layout := range []renditionLayoutType{Effect, Gradient, NamedGradient} {
		for _, format := range []string{PixFmtARGB, ""} {
			items = append(items, syntheticRendition{[]uint16{uint16(len(items) + 1)},
				syntheticCSI(t, "drawing", format, layout, 0, 0, nil, []byte("unverified stops"))})
		}
	}
	input := writeCatalog(t, syntheticCatalog(t, items, []renditionAttributeType{Identifier}))
	for _, conf := range []*Config{{MetadataOnly: true}, {Export: true}, {Export: true, Raw: true}} {
		conf.Output = t.TempDir()
		a, err := Parse(input, conf)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range a.PlanExport(conf.Output) {
			want := "unsupported"
			if conf.Raw {
				want = "exported"
			}
			if entry.Status != want {
				t.Fatalf("layout status = %+v, want %s", entry, want)
			}
		}
		if s := a.Stats(); s.DecodeFailures != 0 || s.ExportFailures != 0 {
			t.Fatalf("unsupported layouts counted as failures: %+v", s)
		}
	}
}

// These opt-in checks keep real catalogs outside the repository. Ordinary tests
// use synthetic inputs; set IPSW_CAR_TEST_CATALOGS to a path-separated list.
func TestSystemCatalogExport(t *testing.T) {
	paths := filepath.SplitList(os.Getenv("IPSW_CAR_TEST_CATALOGS"))
	if len(paths) == 0 {
		t.Skip("set IPSW_CAR_TEST_CATALOGS to external CAR paths")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			conf := &Config{Export: true, Output: t.TempDir()}
			a, err := Parse(path, conf)
			if err != nil {
				t.Fatal(err)
			}
			plan := a.PlanExport(conf.Output)
			if len(plan) == 0 || len(plan) != a.Stats().Total {
				t.Fatal("missing inventory")
			}
			hashes := make(map[string][32]byte)
			unsupported := make(map[string]int)
			byKey := make(map[string]*Rendition)
			for i := range a.ImageDB {
				byKey[renditionKey(a.ImageDB[i].Key)] = &a.ImageDB[i]
			}
			for _, entry := range plan {
				switch entry.Status {
				case "unsupported":
					unsupported[entry.Error]++
				case "exported":
					data, err := os.ReadFile(entry.Path)
					if err != nil {
						t.Fatalf("output %s: %v", entry.Name, err)
					}
					hashes[entry.Path] = sha256.Sum256(data)
					rend := &a.ImageDB[entry.index]
					if original, ok := rend.Asset.([]byte); ok && !bytes.Equal(data, original) {
						t.Fatalf("original bytes changed: %s", entry.Name)
					}
					if _, ok := rend.Asset.(image.Image); ok {
						cfg, err := png.DecodeConfig(bytes.NewReader(data))
						if err != nil || cfg.Width != int(entry.Width) || cfg.Height != int(entry.Height) {
							t.Fatalf("PNG dimensions %s: %v, %v", entry.Name, cfg, err)
						}
					}
					if rend.isRawLink() {
						source := byKey[renditionKey(entry.SourceKey)]
						if source == nil {
							t.Fatalf("missing raw source for %s", entry.Name)
						}
						original, ok := source.Asset.([]byte)
						if !ok || !bytes.Equal(data, original) || len(entry.Crops) != 0 {
							t.Fatalf("raw link changed target bytes: %s", entry.Name)
						}
					}
				default:
					t.Errorf("%s: %s: %s", entry.Name, entry.Status, entry.Error)
				}
				if entry.Compression == RLE.String() && entry.Status != "exported" {
					t.Errorf("RLE rendition did not export: %s", entry.Name)
				}
			}
			if len(hashes) == 0 {
				t.Fatal("catalog exported no files")
			}
			t.Logf("%d renditions, %d files, unsupported: %v", len(plan), len(hashes), unsupported)
			a.exportRenditions(a.indexRenditions())
			for _, entry := range a.PlanExport(conf.Output) {
				if hash, ok := hashes[entry.Path]; ok {
					data, err := os.ReadFile(entry.Path)
					if err != nil || entry.Status != "exported" || sha256.Sum256(data) != hash {
						t.Errorf("repeat export changed or failed %s: %v", entry.Name, err)
					}
				}
			}
		})
	}
}

func TestExportFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset.raw")
	control := filepath.Join(t.TempDir(), "control")
	if err := os.WriteFile(control, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(control)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRendition(path, []byte("new"), SRGB); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != want.Mode().Perm() {
		t.Fatalf("new export mode should respect 0644 and umask: %v, %v", info, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := writeRendition(path, []byte{byte(i)}, SRGB); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("export changed private permissions: %v, %v", info, err)
		}
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeRendition(path, []byte("new"), SRGB); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("export lost existing mode: %v, %v", info, err)
	}
}
