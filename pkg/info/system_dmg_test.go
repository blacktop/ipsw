package info

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/devicetree"
	"github.com/blacktop/ipsw/pkg/plist"
)

func TestBoardProductFromDeviceTree(t *testing.T) {
	i := multiSystemInfo()
	i.Plists.BuildManifest.SupportedProductTypes = []string{"Mac99,1", "Mac99,2"}
	i.Plists.BuildManifest.ProductBuildVersion = "99A1"
	i.DeviceTrees = make(map[string]*devicetree.DeviceTree)
	for idx := range i.Plists.BuildIdentities {
		bi := &i.Plists.BuildIdentities[idx]
		product := bi.ApProductType
		bi.ApProductType = ""
		bi.Manifest["KernelCache"] = plist.IdentityManifest{Info: map[string]any{"Path": "kernelcache." + bi.Info.DeviceClass}}
		i.DeviceTrees[bi.Info.DeviceClass] = &devicetree.DeviceTree{
			"device-tree": devicetree.Properties{
				"children":   []devicetree.DeviceTree{},
				"model":      product,
				"compatible": []string{product, bi.Info.DeviceClass, "AppleARM"},
			},
		}
	}
	for _, selector := range []string{"J992AP", "mac99,2"} {
		product := i.ProductType(selector)
		if product != "Mac99,2" {
			t.Fatalf("ProductType(%q) = %q", selector, product)
		}
		folder, err := i.GetFolder(product)
		if err != nil || folder != "99A1__Mac99,2" {
			t.Fatalf("folder = %q, %v", folder, err)
		}
		if paths := i.GetKernelCacheForDevice(product); !reflect.DeepEqual(paths, []string{"kernelcache.j992ap"}) {
			t.Fatalf("kernelcache paths = %v", paths)
		}
		selected, err := i.SelectDevice(selector)
		if err != nil {
			t.Fatal(err)
		}
		if path, err := selected.GetSystemOsDmg(); err != nil || path != "special.dmg.aea" {
			t.Fatalf("SystemOS = %q, %v", path, err)
		}
	}
	delete(i.DeviceTrees, "j992ap")
	i.DeviceTrees["unavailable"] = nil
	if product := i.ProductType("J992AP"); product != "J992AP" {
		t.Fatalf("resolved board without a matching DeviceTree: %q", product)
	}
}

func multiSystemInfo() *Info {
	var identities []plist.BuildIdentity
	for _, variant := range []string{"Customer Erase Install (IPSW)", "Customer Upgrade Install (IPSW)", "macOS Customer"} {
		for idx, path := range []string{"common.dmg.aea", "special.dmg.aea"} {
			identities = append(identities, plist.BuildIdentity{
				ApProductType: []string{"Mac99,1", "Mac99,2"}[idx],
				Info:          plist.IdentityInfo{DeviceClass: []string{"j991ap", "j992ap"}[idx], Variant: variant},
				Manifest: map[string]plist.IdentityManifest{
					"Cryptex1,SystemOS": {Info: map[string]any{"Path": path}},
				},
			})
		}
	}
	return &Info{Plists: &plist.Plists{BuildManifest: &plist.BuildManifest{BuildIdentities: identities}}}
}

func TestSharedSystemFallbackDoesNotGuessBetweenImages(t *testing.T) {
	i := multiSystemInfo()
	if _, err := i.SelectDeviceOrSharedSystem("Mac99,3"); err == nil {
		t.Fatal("unmatched device chose an ambiguous image")
	}
	if _, err := i.SelectDeviceOrSharedSystem(""); !errors.Is(err, ErrAmbiguousSystemOS) {
		t.Fatalf("missing selector: %v", err)
	}
	for idx := range i.Plists.BuildIdentities {
		i.Plists.BuildIdentities[idx].Manifest["Cryptex1,SystemOS"].Info["Path"] = "shared.dmg"
		// DSC-only fallback must remain usable when the kernels differ.
		i.Plists.BuildIdentities[idx].Manifest["KernelCache"] = plist.IdentityManifest{
			Info: map[string]any{"Path": "kernelcache." + i.Plists.BuildIdentities[idx].ApProductType},
		}
	}
	selected, err := i.SelectDeviceOrSharedSystem("Mac99,3")
	if err != nil || selected != i {
		t.Fatalf("shared fallback: %v, %v", selected, err)
	}
	if _, err := i.SelectDevice("Mac99,3"); err == nil {
		t.Fatal("shared fallback weakened explicit selection")
	}
}

func TestSystemOSDeviceSelection(t *testing.T) {
	i := multiSystemInfo()
	dmgs, err := i.GetSystemOsDmgs()
	want := []SystemOSDMG{
		{Path: "common.dmg.aea", Devices: []string{"Mac99,1"}, Boards: []string{"j991ap"}},
		{Path: "special.dmg.aea", Devices: []string{"Mac99,2"}, Boards: []string{"j992ap"}},
	}
	if err != nil || !reflect.DeepEqual(dmgs, want) {
		t.Fatalf("enumeration = %+v, %v; want %+v", dmgs, err, want)
	}
	if path, err := i.GetSystemOsDmg(); err == nil || errors.Is(err, ErrorCryptexNotFound) || !strings.Contains(err.Error(), "Mac99,2") || path != "" {
		t.Fatalf("ambiguous selection = %q, %v", path, err)
	}
	for _, device := range []string{"Mac99,2", "mac99,2", "J992AP"} {
		selected, err := i.ForDevice(device)
		if err != nil {
			t.Fatal(err)
		}
		path, err := selected.GetSystemOsDmg()
		if err != nil || path != "special.dmg.aea" {
			t.Fatalf("%s: %q, %v", device, path, err)
		}
		if len(selected.Plists.BuildIdentities) != 3 {
			t.Fatal("lost install variants")
		}
	}
	if len(i.Plists.BuildIdentities) != 6 {
		t.Fatal("selection mutated source metadata")
	}
	for _, device := range []string{"Mac99", "j992", "Mac99,3"} {
		if _, err := i.ForDevice(device); err == nil {
			t.Fatalf("accepted unknown/partial selector %q", device)
		}
	}
}

func TestSystemOSInvalidAndMissingMetadata(t *testing.T) {
	for _, i := range []*Info{nil, {}, {Plists: &plist.Plists{}}} {
		if _, err := i.GetSystemOsDmgs(); err == nil {
			t.Fatal("accepted missing metadata")
		}
	}
	i := multiSystemInfo()
	for _, value := range []any{nil, "", 123} {
		i.Plists.BuildIdentities[0].Manifest["Cryptex1,SystemOS"] = plist.IdentityManifest{Info: map[string]any{"Path": value}}
		if _, err := i.GetSystemOsDmg(); err == nil || errors.Is(err, ErrorCryptexNotFound) {
			t.Fatalf("bad path %v: %v", value, err)
		}
	}
	i.Plists.BuildManifest.BuildIdentities = nil
	if _, err := i.GetSystemOsDmg(); !errors.Is(err, ErrorCryptexNotFound) {
		t.Fatalf("missing component: %v", err)
	}
}

func TestSystemOSSharedImageAndLegacyProduct(t *testing.T) {
	i := multiSystemInfo()
	for idx := range i.Plists.BuildIdentities {
		i.Plists.BuildIdentities[idx].Manifest["Cryptex1,SystemOS"].Info["Path"] = "shared.dmg"
	}
	if path, err := i.GetSystemOsDmg(); err != nil || path != "shared.dmg" {
		t.Fatalf("shared image: %q, %v", path, err)
	}
	i.Plists.BuildManifest.SupportedProductTypes = []string{"iPhone99,1"}
	for idx := range i.Plists.BuildIdentities {
		i.Plists.BuildIdentities[idx].ApProductType = ""
	}
	if _, err := i.ForDevice("iPhone99,1"); err != nil {
		t.Fatalf("legacy single product: %v", err)
	}
}

func TestSystemOSInfoShowsBoardSelectors(t *testing.T) {
	i := multiSystemInfo()
	i.Plists.Restore = &plist.Restore{}
	for idx := range i.Plists.BuildIdentities {
		i.Plists.BuildIdentities[idx].ApProductType = ""
	}
	output := i.String()
	for _, want := range []string{
		"SystemOS       = common.dmg.aea [j991ap]",
		"SystemOS       = special.dmg.aea [j992ap]",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("info output missing %q:\n%s", want, output)
		}
	}
	selected, err := i.ForDevice("j992ap")
	if err != nil {
		t.Fatal(err)
	}
	if path, err := selected.GetSystemOsDmg(); err != nil || path != "special.dmg.aea" {
		t.Fatalf("displayed board selector resolved to %q, %v", path, err)
	}
}

func TestProductTypeResolvesBoards(t *testing.T) {
	i := multiSystemInfo()
	for device, want := range map[string]string{"": "", "J992AP": "Mac99,2", "mac99,2": "Mac99,2", "Mac99,3": "Mac99,3"} {
		if got := i.ProductType(device); got != want {
			t.Errorf("ProductType(%q) = %q, want %q", device, got, want)
		}
	}
}

func TestSystemOSMissingBuildManifestIsCryptexNotFound(t *testing.T) {
	for _, i := range []*Info{nil, {}, {Plists: &plist.Plists{}}} {
		if _, err := i.GetSystemOsDmg(); !errors.Is(err, ErrorCryptexNotFound) {
			t.Fatalf("missing BuildManifest must allow the filesystem fallback: %v", err)
		}
	}
}
