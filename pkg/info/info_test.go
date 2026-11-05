package info

import (
	"slices"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/devicetree"
	"github.com/blacktop/ipsw/pkg/ota/types"
	"github.com/blacktop/ipsw/pkg/plist"
)

func TestGetFolderReportsDeviceTreeError(t *testing.T) {
	dtree := devicetree.DeviceTree{}
	inf := &Info{
		Plists:      &plist.Plists{BuildManifest: &plist.BuildManifest{}},
		DeviceTrees: map[string]*devicetree.DeviceTree{"DeviceTree.synthetic": &dtree},
	}
	_, folderErr := inf.GetFolder()
	_, kernelErr := inf.GetKernelCacheFolders("kernelcache.synthetic")
	for api, err := range map[string]error{"GetFolder": folderErr, "GetKernelCacheFolders": kernelErr} {
		if err == nil || !strings.Contains(err.Error(), "DeviceTree.synthetic") || !strings.Contains(err.Error(), "node children") {
			t.Fatalf("%s error = %v", api, err)
		}
	}
}

func TestKernelCacheBuildManifestFallbackForSingleDeviceIPSW(t *testing.T) {
	inf := &Info{
		Plists: &plist.Plists{
			BuildManifest: &plist.BuildManifest{
				SupportedProductTypes: []string{"iPhone8,2"},
				BuildIdentities: []plist.BuildIdentity{
					testBuildIdentity("", "n66ap", "kernelcache.release.n66"),
					testBuildIdentity("", "n66ap", "kernelcache.release.n66"),
					testBuildIdentity("", "n66map", "kernelcache.release.n66m"),
				},
			},
		},
	}

	kernels := inf.GetKernelCacheForDevice("iPhone8,2")
	wantKernels := []string{"kernelcache.release.n66", "kernelcache.release.n66m"}
	if !slices.Equal(kernels, wantKernels) {
		t.Fatalf("GetKernelCacheForDevice() = %#v, want %#v", kernels, wantKernels)
	}

	devices := inf.GetDevicesForKernelCache("kernelcache.release.n66")
	wantDevices := []string{"iPhone8,2"}
	if !slices.Equal(devices, wantDevices) {
		t.Fatalf("GetDevicesForKernelCache() = %#v, want %#v", devices, wantDevices)
	}

	if got := inf.GetKernelCacheFileName("kernelcache.release.n66"); got != "kernelcache.release.n66" {
		t.Fatalf("GetKernelCacheFileName() = %q, want original kernelcache name", got)
	}
}

func TestKernelCacheBuildManifestFallbackUsesProductType(t *testing.T) {
	inf := &Info{
		Plists: &plist.Plists{
			BuildManifest: &plist.BuildManifest{
				SupportedProductTypes: []string{"iPhone1,1", "iPhone1,2"},
				BuildIdentities: []plist.BuildIdentity{
					testBuildIdentity("iPhone1,1", "m68ap", "kernelcache.release.s5l8900x"),
					testBuildIdentity("iPhone1,2", "n82ap", "kernelcache.release.s5l8900x"),
				},
			},
		},
	}

	kernels := inf.GetKernelCacheForDevice("iPhone1,2")
	wantKernels := []string{"kernelcache.release.s5l8900x"}
	if !slices.Equal(kernels, wantKernels) {
		t.Fatalf("GetKernelCacheForDevice() = %#v, want %#v", kernels, wantKernels)
	}

	devices := inf.GetDevicesForKernelCache("kernelcache.release.s5l8900x")
	wantDevices := []string{"iPhone1,1", "iPhone1,2"}
	if !slices.Equal(devices, wantDevices) {
		t.Fatalf("GetDevicesForKernelCache() = %#v, want %#v", devices, wantDevices)
	}
}

func TestKernelCacheFileNameDistinguishesVariants(t *testing.T) {
	variants := []string{"release", "research", "development"}
	inf := &Info{Plists: &plist.Plists{BuildManifest: &plist.BuildManifest{
		SupportedProductTypes: []string{"iPhone12,1"},
	}}}
	for _, variant := range variants {
		inf.Plists.BuildIdentities = append(inf.Plists.BuildIdentities,
			testBuildIdentity("iPhone12,1", "n104ap", "kernelcache."+variant+".iphone12b"))
	}
	for _, variant := range variants {
		path := "kernelcache." + variant + ".iphone12b"
		if got := inf.GetDevicesForKernelCache(path); !slices.Equal(got, []string{"iPhone12,1"}) {
			t.Fatalf("GetDevicesForKernelCache(%q) = %v, want iPhone12,1", path, got)
		}
		want := "kernelcache." + variant + ".iPhone12,1"
		if got := inf.GetKernelCacheFileName(path); got != want {
			t.Errorf("GetKernelCacheFileName(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestKernelCacheFileNameOnlyRetainsCollidingVariants(t *testing.T) {
	inf := &Info{Plists: &plist.Plists{BuildManifest: &plist.BuildManifest{
		SupportedProductTypes: []string{"iPhone8,2"},
		BuildIdentities: []plist.BuildIdentity{
			testBuildIdentity("", "n66ap", "kernelcache.release.n66"),
			testBuildIdentity("", "n66map", "kernelcache.release.n66m"),
			testBuildIdentity("", "n66ap", "kernelcache.research.n66"),
		},
	}}}
	for _, path := range []string{"kernelcache.release.n66", "kernelcache.release.n66m"} {
		if got := inf.GetKernelCacheFileName(path); got != path {
			t.Errorf("GetKernelCacheFileName(%q) = %q, want original name", path, got)
		}
	}
	if got := inf.GetKernelCacheFileName("kernelcache.research.n66"); got != "kernelcache.research.iPhone8,2" {
		t.Errorf("research filename = %q, want kernelcache.research.iPhone8,2", got)
	}
}

func testBuildIdentity(productType, deviceClass, kernelPath string) plist.BuildIdentity {
	return plist.BuildIdentity{
		ApProductType: productType,
		Info: plist.IdentityInfo{
			DeviceClass: deviceClass,
		},
		Manifest: map[string]plist.IdentityManifest{
			"KernelCache": {
				Info: map[string]any{
					"Path": kernelPath,
				},
			},
		},
	}
}

// TestGetFolderSimulatorRuntimeUsesAssetType pins the folder shape for
// simulator-runtime OTAs. It is the leading path segment of every entry in the
// `ipsw ota extract --dyld --json` report, so the trailing token being the
// MobileAsset type (`iOSSimulatorRuntime`) and NOT a short platform name
// (`iOS`) is part of that published contract.
func TestGetFolderSimulatorRuntimeUsesAssetType(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		want       string
	}{
		{
			name:       "iOS simulator runtime",
			identifier: "com.apple.MobileAsset.iOSSimulatorRuntime",
			want:       "18.2_22C150_iOSSimulatorRuntime",
		},
		{
			name:       "watchOS simulator runtime",
			identifier: "com.apple.MobileAsset.watchOSSimulatorRuntime",
			want:       "18.2_22C150_watchOSSimulatorRuntime",
		},
		{
			name:       "identifier without the MobileAsset prefix falls back",
			identifier: "com.example.Something",
			want:       "18.2_22C150_Simulator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inf := &Info{
				Plists: &plist.Plists{
					Type: "OTA",
					OTAInfo: &plist.OTAInfo{
						CFBundleName:       "SimulatorRuntimeAsset",
						CFBundleIdentifier: tt.identifier,
						MobileAssetProperties: types.Asset{
							SimulatorVersion: "18.2",
							Build:            "22C150",
						},
					},
				},
			}

			got, err := inf.GetFolder()
			if err != nil {
				t.Fatalf("GetFolder() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("GetFolder() = %q, want %q", got, tt.want)
			}
		})
	}
}

// requireUnsafeFolder asserts a folder API refused a metadata-derived name.
// The predicate itself is covered by utils.TestValidatePathComponent.
func requireUnsafeFolder(t *testing.T, api string, folders []string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "unsafe output folder name") || folders != nil {
		t.Fatalf("%s = %q, %v; want unsafe folder error", api, folders, err)
	}
}

func folderOrNil(folder string) []string {
	if folder == "" {
		return nil
	}
	return []string{folder}
}

func TestGetFolderValidatesMetadata(t *testing.T) {
	manifest := func(build string, devices ...string) *plist.Plists {
		return &plist.Plists{BuildManifest: &plist.BuildManifest{ProductBuildVersion: build, SupportedProductTypes: devices}}
	}
	for _, tt := range []struct {
		name   string
		plists *plist.Plists
		want   string // empty means GetFolder must refuse the name
	}{
		{"normal", manifest("22A3354", "iPhone17,1"), "22A3354__iPhone17,1"},
		{"device escape", manifest("A", "x/../../escaped"), ""},
		{"build escape", manifest("22A3354/../..", "iPhone17,1"), ""},
		{"simulator escape", &plist.Plists{Type: "OTA", OTAInfo: &plist.OTAInfo{
			CFBundleName:          "SimulatorRuntimeAsset",
			CFBundleIdentifier:    "com.apple.MobileAsset.iOSSimulatorRuntime",
			MobileAssetProperties: types.Asset{SimulatorVersion: "../../escaped", Build: "22C150"},
		}}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			folder, err := (&Info{Plists: tt.plists}).GetFolder()
			if tt.want == "" {
				requireUnsafeFolder(t, "GetFolder()", folderOrNil(folder), err)
			} else if err != nil || folder != tt.want {
				t.Fatalf("GetFolder() = %q, %v; want %q", folder, err, tt.want)
			}
		})
	}
}

func TestDeviceTreeFolderAPIsValidateMetadata(t *testing.T) {
	const board = "n66ap"
	for _, tt := range []struct {
		name, product, build string
		want                 string // per-device folder; empty means refused
		wantGroup            string // GetFolder; empty means refused
	}{
		{"normal", "iPhone8,2", "A", "iPhone8,2_N66AP_A", "A__iPhone8,2"},
		{"product traversal", "x/../../escaped", "A", "", "A__0,0"},
		{"build traversal", "iPhone8,2", "22A3354/../..", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dtree := devicetree.DeviceTree{"device-tree": devicetree.Properties{
				"children": []devicetree.DeviceTree{}, "model": tt.product, "compatible": []string{board},
			}}
			inf := &Info{
				Plists: &plist.Plists{BuildManifest: &plist.BuildManifest{
					ProductBuildVersion: tt.build,
					BuildIdentities:     []plist.BuildIdentity{testBuildIdentity(tt.product, board, "kernelcache.synthetic")},
				}},
				DeviceTrees: map[string]*devicetree.DeviceTree{"DeviceTree.synthetic": &dtree},
			}
			check := func(api string, folders []string, err error, want string) {
				t.Helper()
				if want == "" {
					requireUnsafeFolder(t, api, folders, err)
				} else if err != nil || !slices.Equal(folders, []string{want}) {
					t.Fatalf("%s = %q, %v; want %q", api, folders, err, want)
				}
			}
			folders, err := inf.GetFolders()
			check("GetFolders()", folders, err, tt.want)
			folders, err = inf.GetKernelCacheFolders("Firmware/kernelcache.synthetic")
			check("GetKernelCacheFolders()", folders, err, tt.want)
			folder, err := inf.GetFolderForFile("Firmware/kernelcache.synthetic")
			check("GetFolderForFile()", folderOrNil(folder), err, tt.want)
			folder, err = inf.GetFolder()
			check("GetFolder()", folderOrNil(folder), err, tt.wantGroup)
		})
	}
}

func TestAbbreviatedDevListToleratesMissingModelSeparator(t *testing.T) {
	devices := []string{"iPhone1,1", "iPhone1x"}
	if got := getAbbreviatedDevListFolder(devices); got != "iPhone1,1_iPhone1x" {
		t.Fatalf("getAbbreviatedDevListFolder() = %q", got)
	}
	if got := getAbbreviatedDevList(devices); got != "iPhone1,1_iPhone1x" {
		t.Fatalf("getAbbreviatedDevList() = %q", got)
	}
}
