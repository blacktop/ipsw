package info

import (
	"slices"
	"testing"

	"github.com/blacktop/ipsw/pkg/ota/types"
	"github.com/blacktop/ipsw/pkg/plist"
)

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
